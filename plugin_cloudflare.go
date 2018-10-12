package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"
)

const (
	defaultTimeout = 5 * time.Second
)

type UpstreamHTTPS struct {
	client   *http.Client
	endpoint *url.URL
}

// NewUpstreamHTTPS creates a new DNS over HTTPS upstream from hostname
func NewUpstreamHTTPS(endpoint string) (*UpstreamHTTPS, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// Update TLS and HTTP client configuration
	tls := &tls.Config{ServerName: u.Hostname()}
	transport := &http.Transport{
		TLSClientConfig:    tls,
		DisableCompression: true,
		MaxIdleConns:       1,
	}
	http2.ConfigureTransport(transport)

	client := &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}

	return &UpstreamHTTPS{client: client, endpoint: u}, nil
}

// Exchange provides an implementation for the Upstream interface
func (u *UpstreamHTTPS) Exchange(query *dns.Msg) (*dns.Msg, error) {
	queryBuf, err := query.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack DNS query")
	}

	// No content negotiation for now, use DNS wire format
	buf, backendErr := u.exchangeWireformat(queryBuf)
	if backendErr == nil {
		response := &dns.Msg{}
		if err := response.Unpack(buf); err != nil {
			return nil, errors.Wrap(err, "failed to unpack DNS response from body")
		}

		response.Id = query.Id
		return response, nil
	}

	dlog.Errorf("failed to connect to an HTTPS backend %q", u.endpoint)
	return nil, backendErr
}

// Perform message exchange with the default UDP wireformat defined in current draft
// https://datatracker.ietf.org/doc/draft-ietf-doh-dns-over-https
func (u *UpstreamHTTPS) exchangeWireformat(msg []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", u.endpoint.String(), bytes.NewBuffer(msg))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create an HTTPS request")
	}

	req.Header.Add("Content-Type", "application/dns-udpwireformat")
	req.Host = u.endpoint.Hostname()

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform an HTTPS request")
	}

	// Check response status code
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status code %d", resp.StatusCode)
	}

	// Read wireformat response from the body
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the response body")
	}

	return buf, nil
}

type PluginCloudFlare struct {
	Upstreams []*UpstreamHTTPS
}

func (plugin *PluginCloudFlare) Name() string {
	return "CloudFlareHttpDNS"
}

func (plugin *PluginCloudFlare) Description() string {
	return "Route queries to CloudFlare Http DNS Server"
}

func (plugin *PluginCloudFlare) Init(proxy *Proxy) error {
	upstreams := []string{"https://cloudflare-dns.com/dns-query", "https://1.0.0.1/dns-query"}
	upstreamList := make([]*UpstreamHTTPS, 0)
	for _, url := range upstreams {
		dlog.Infof("Adding DNS upstream :%s", url)
		upstream, err := NewUpstreamHTTPS(url)
		if err != nil {
			return errors.Wrap(err, "failed to create HTTPS upstream")
		}
		upstreamList = append(upstreamList, upstream)
	}
	plugin.Upstreams = upstreamList
	return nil
}

func (plugin *PluginCloudFlare) Drop() error {
	return nil
}

func (plugin *PluginCloudFlare) Reload() error {
	return nil
}

func (plugin *PluginCloudFlare) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	var respMsg *dns.Msg
	var err error
	for _, upstream := range plugin.Upstreams {
		respMsg, err = upstream.Exchange(msg)
		if err == nil {
			pluginsState.synthResponse = respMsg
			pluginsState.action = PluginsActionSynth
			return nil
		}else{
			dlog.Errorf("get upstream :%s", err)
		}
	}

	return err
}

