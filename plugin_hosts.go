package main

import (
	"net"
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginHosts struct {
	patternMatcher *PatternMatcher
}

func (plugin *PluginHosts) Name() string {
	return "Hosts"
}

func (plugin *PluginHosts) Description() string {
	return "Route queries matching specific domains to a dedicated set of record"
}

func (plugin *PluginHosts) Init(proxy *Proxy) error {
	dlog.Noticef("Loading Hosts %d rules", len(proxy.db.GetHosts()))
	plugin.patternMatcher = NewPatternPatcher()
	for _, v := range proxy.db.GetHosts() {
		if _, err := plugin.patternMatcher.Add(v.GetPattern(), v.GetData()); err != nil {
			dlog.Error(err)
			continue
		}
	}
	return nil
}

func (plugin *PluginHosts) Drop() error {
	return nil
}

func (plugin *PluginHosts) Reload() error {
	return nil
}

func (plugin *PluginHosts) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))

	reason, val := plugin.patternMatcher.Eval(qName)
	if val != nil {
		ttl := uint32(60)
		synth, err := EmptyResponseFromMessage(msg)
		if err != nil {
			return err
		}
		ip := net.ParseIP(strings.TrimSpace(val.(string)))
		if question.Qtype == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ip
			synth.Answer = []dns.RR{rr}
		} else {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ip
			synth.Answer = []dns.RR{rr}
		}
		pluginsState.synthResponse = synth
		pluginsState.action = PluginsActionSynth
		dlog.Debugf("reason: %s, val: %s", reason, val)
	}
	return nil
}
