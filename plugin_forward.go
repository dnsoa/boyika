package main

import (
	"math/rand"
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type ForwardMatcher struct {
	servers        []string
	patternMatcher *PatternMatcher
}

type PluginForward struct {
	forwardMatcher []*ForwardMatcher
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	//plugin.servers = []string{"8.8.8.8:53"}
	plugin.forwardMatcher = make([]*ForwardMatcher, 0)
	for _, finder := range proxy.db.GetForward() {
		matcher := &ForwardMatcher{
			servers:        finder.GetName(),
			patternMatcher: NewPatternPatcher(),
		}
		for _, name := range finder.GetDomain() {
			if _, err := matcher.patternMatcher.Add(name, true); err != nil {
				dlog.Error(err)
				continue
			}
		}
		plugin.forwardMatcher = append(plugin.forwardMatcher, matcher)
	}

	return nil
}

func (plugin *PluginForward) Drop() error {
	return nil
}

func (plugin *PluginForward) Reload() error {
	return nil
}

func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))

	for _, matcher := range plugin.forwardMatcher {

		if len(matcher.servers) == 0 {
			continue
		}
		server := matcher.servers[rand.Intn(len(matcher.servers))]

		reason, val := matcher.patternMatcher.Eval(qName)
		if val != nil {
			dlog.Debugf("Match forward rules %s[%s] => %s", qName, server, reason)
			respMsg, err := dns.Exchange(msg, server)
			if err != nil {
				dlog.Errorf("Error exchange server[%s]: %s", server, err)
				return err
			}
			pluginsState.synthResponse = respMsg
			pluginsState.action = PluginsActionSynth
			break
		}
	}
	return nil
}
