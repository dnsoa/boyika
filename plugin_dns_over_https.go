package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/jedisct1/dlog"
	jsondns "github.com/m13253/dns-over-https/json-dns"
	"github.com/miekg/dns"
)

type DnsOverHttps struct {
	servers        []string
	patternMatcher *PatternMatcher
}

type PluginDoh struct {
	cookieJar     http.CookieJar
	httpClientMux *sync.RWMutex
	httpTransport *http.Transport
	httpClient    *http.Client
	matcher       []*DnsOverHttps
}

func (plugin *PluginDoh) Name() string {
	return "dns over https"
}

func (plugin *PluginDoh) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginDoh) Init(proxy *Proxy) error {
	var err error
	plugin.cookieJar, err = cookiejar.New(nil)
	if err != nil {
		return err
	}
	plugin.httpClientMux = new(sync.RWMutex)
	err = plugin.newHTTPClient()
	if err != nil {
		return err
	}
	plugin.matcher = make([]*DnsOverHttps, 0)
	for _, finder := range proxy.db.GetDoh() {
		matcher := &DnsOverHttps{
			servers:        finder.GetName(),
			patternMatcher: NewPatternPatcher(),
		}
		for _, name := range finder.GetDomain() {
			if _, err := matcher.patternMatcher.Add(name, true); err != nil {
				dlog.Error(err)
				continue
			}
		}
		plugin.matcher = append(plugin.matcher, matcher)
	}

	return nil
}

func (plugin *PluginDoh) Drop() error {
	return nil
}

func (plugin *PluginDoh) Reload() error {
	return nil
}

func (plugin *PluginDoh) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))
	qType := dns.TypeToString[questions[0].Qtype]

	udpSize := uint16(512)
	if opt := msg.IsEdns0(); opt != nil {
		udpSize = opt.UDPSize()
	}

	for _, matcher := range plugin.matcher {

		if len(matcher.servers) == 0 {
			continue
		}
		server := matcher.servers[rand.Intn(len(matcher.servers))]

		reason, val := matcher.patternMatcher.Eval(qName)
		if val != nil {
			server = strings.Replace(server, "{name}", qName, -1)
			server = strings.Replace(server, "{type}", qType, -1)
			dlog.Debugf("Match doh rules %s[%s] => %s", qName, server, reason)
			req, err := http.NewRequest("GET", server, nil)
			if err != nil {
				err1 := plugin.newHTTPClient()
				if err != nil {
					return err1
				}
				return err
			}
			req.Header.Set("Accept", "application/dns-json")
			req.Header.Set("User-Agent", "boyika -- https://github.com/dnsoa/boyika")
			plugin.httpClientMux.RLock()
			resp, err := plugin.httpClient.Do(req)
			plugin.httpClientMux.RUnlock()
			if err != nil {
				return err
			}
			if resp.StatusCode != 200 {
				return fmt.Errorf("http status code : %d", resp.StatusCode)
			}
			body, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				return err
			}
			var respJSON jsondns.Response

			err = json.Unmarshal(body, &respJSON)
			if err != nil {
				dlog.Errorf("Unmarshal : %s", err)
				return err
			}
			reply := jsondns.PrepareReply(msg)

			respMsg := jsondns.Unmarshal(reply, &respJSON, udpSize, 255)
			pluginsState.synthResponse = respMsg
			pluginsState.action = PluginsActionSynth
			break
		}
	}
	return nil
}

func (plugin *PluginDoh) newHTTPClient() error {
	plugin.httpClientMux.Lock()
	defer plugin.httpClientMux.Unlock()

	if plugin.httpTransport != nil {
		plugin.httpTransport.CloseIdleConnections()
	}
	dialer := &net.Dialer{
		Timeout:   time.Duration(30) * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
		//Resolver:  plugin.bootstrapResolver,
	}
	plugin.httpTransport = &http.Transport{
		DialContext:           dialer.DialContext,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
		TLSHandshakeTimeout:   time.Duration(30) * time.Second,
	}

	err := http2.ConfigureTransport(plugin.httpTransport)
	if err != nil {
		return err
	}
	plugin.httpClient = &http.Client{
		Transport: plugin.httpTransport,
		Jar:       plugin.cookieJar,
	}
	return nil
}
