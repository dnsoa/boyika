package main

import (
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginBlockName struct {
	patternMatcher *PatternMatcher
}

func (plugin *PluginBlockName) Name() string {
	return "BlockName"
}

func (plugin *PluginBlockName) Description() string {
	return "Block DNS queries matching name patterns"
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	dlog.Noticef("Loading BlockName config, %+v", proxy.db.GetBlockName())
	plugin.patternMatcher = NewPatternPatcher()
	for _, name := range proxy.db.GetBlockName() {
		if _, err := plugin.patternMatcher.Add(name, true); err != nil {
			dlog.Error(err)
			continue
		}
	}
	return nil
}

func (plugin *PluginBlockName) Drop() error {
	return nil
}

func (plugin *PluginBlockName) Reload() error {
	return nil
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))

	reason, val := plugin.patternMatcher.Eval(qName)
	if val != nil {
		pluginsState.action = PluginsActionReject
		dlog.Debugf("blockname : %s", reason)
	}
	return nil
}
