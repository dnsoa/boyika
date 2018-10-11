package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

// DNSResponseJSON is a rough translation of the Google DNS over HTTP API as it currently exists.
type DNSResponseJSON struct {
	Status           int32         `json:"Status,omitempty"`
	TC               bool          `json:"TC,omitempty"`
	RD               bool          `json:"RD,omitempty"`
	RA               bool          `json:"RA,omitempty"`
	AD               bool          `json:"AD,omitempty"`
	CD               bool          `json:"CD,omitempty"`
	Question         []DNSQuestion `json:"Question,omitempty"`
	Answer           []DNSRR       `json:"Answer,omitempty"`
	Authority        []DNSRR       `json:"Authority,omitempty"`
	Additional       []DNSRR       `json:"Additional,omitempty"`
	EdnsClientSubnet string        `json:"edns_client_subnet,omitempty"`
	Comment          string        `json:"Comment,omitempty"`
}

// DNSQuestion is the JSON encoding of a DNS request
type DNSQuestion struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
}

// DNSRR is the JSON encoding of an RRset as returned by Google.
type DNSRR struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
	TTL  int32  `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

//https://github.com/googlehosts/hosts/blob/master/hosts-files/hosts
type PluginGoogleHttpsDNS struct {
}

func (plugin *PluginGoogleHttpsDNS) Name() string {
	return "GoogleHttpsDNS"
}

func (plugin *PluginGoogleHttpsDNS) Description() string {
	return "Route queries to Google Http DNS Server"
}

func (plugin *PluginGoogleHttpsDNS) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginGoogleHttpsDNS) Drop() error {
	return nil
}

func (plugin *PluginGoogleHttpsDNS) Reload() error {
	return nil
}

func (plugin *PluginGoogleHttpsDNS) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	name := strings.ToLower(StripTrailingDot(questions[0].Name))
	qtype := dns.TypeToString[questions[0].Qtype]
	//questionLen := len(question)

	dlog.Debugf("name = %s qtype=%s", name, qtype)
	respMsg, err := plugin.httpDNSRequestProxy(msg)
	if err != nil {
		return err
	}
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	return nil
}

func (plugin *PluginGoogleHttpsDNS) httpDNSRequestProxy(req *dns.Msg) (*dns.Msg, error) {
	httpreq, err := http.NewRequest(http.MethodGet, "https://dns.google.com/resolve", nil)
	if err != nil {
		dlog.Errorf("Error setting up request: %s", err)
		return nil, err
	}

	qry := httpreq.URL.Query()
	qry.Add("name", req.Question[0].Name)
	qry.Add("type", fmt.Sprintf("%v", req.Question[0].Qtype))
	// qry.Add("cd", cdFlag) // Google DNS-over-HTTPS requires CD to be true - don't set it at all
	qry.Add("edns_client_subnet", "0.0.0.0/0")
	httpreq.URL.RawQuery = qry.Encode()

	httpresp, err := http.DefaultClient.Do(httpreq)
	if err != nil {
		dlog.Errorf("Request to Google DNS over HTTPS: %s", err)
		return nil, err
	}
	defer httpresp.Body.Close() // nolint: errcheck

	// Parse the JSON response
	dnsResp := new(DNSResponseJSON)
	decoder := json.NewDecoder(httpresp.Body)
	err = decoder.Decode(&dnsResp)
	if err != nil {
		dlog.Errorf("Decode Google DNS over HTTPS: %s", err)
		return nil, err
	}

	// Parse the google Questions to DNS RRs
	questions := []dns.Question{}
	for idx, c := range dnsResp.Question {
		questions = append(questions, dns.Question{
			Name:   c.Name,
			Qtype:  uint16(c.Type),
			Qclass: req.Question[idx].Qclass,
		})
	}

	// Parse google RRs to DNS RRs
	answers := []dns.RR{}
	for _, a := range dnsResp.Answer {
		answers = append(answers, plugin.newRR(a))
	}

	// Parse google RRs to DNS RRs
	authorities := []dns.RR{}
	for _, ns := range dnsResp.Authority {
		authorities = append(authorities, plugin.newRR(ns))
	}

	// Parse google RRs to DNS RRs
	extras := []dns.RR{}
	for _, extra := range dnsResp.Additional {
		authorities = append(authorities, plugin.newRR(extra))
	}

	resp := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           (dnsResp.Status == 0),
			Opcode:             dns.OpcodeQuery,
			Authoritative:      false,
			Truncated:          dnsResp.TC,
			RecursionDesired:   dnsResp.RD,
			RecursionAvailable: dnsResp.RA,
			//Zero: false,
			AuthenticatedData: dnsResp.AD,
			CheckingDisabled:  dnsResp.CD,
			Rcode:             int(dnsResp.Status),
		},
		Compress: req.Compress,
		Question: questions,
		Answer:   answers,
		Ns:       authorities,
		Extra:    extras,
	}

	return &resp, nil
}

func (plugin *PluginGoogleHttpsDNS) newRR(a DNSRR) dns.RR {
	var rr dns.RR

	// Build an RR header
	rrhdr := dns.RR_Header{
		Name:     a.Name,
		Rrtype:   uint16(a.Type),
		Class:    dns.ClassINET,
		Ttl:      uint32(a.TTL),
		Rdlength: uint16(len(a.Data)),
	}

	constructor, ok := dns.TypeToRR[uint16(a.Type)]
	if ok {
		// Construct a new RR
		rr = constructor()
		*(rr.Header()) = rrhdr
		switch v := rr.(type) {
		case *dns.A:
			v.A = net.ParseIP(a.Data)
		case *dns.AAAA:
			v.AAAA = net.ParseIP(a.Data)
		}
	} else {
		rr = dns.RR(&dns.RFC3597{
			Hdr:   rrhdr,
			Rdata: a.Data,
		})
	}
	return rr
}
