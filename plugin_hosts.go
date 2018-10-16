package main

import (
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
	dlog.Notice("Loading Hosts config")
	plugin.patternMatcher = NewPatternPatcher()
	for _, v := range proxy.db.GetHosts() {
		if _, err := plugin.patternMatcher.Add(v.GetPattern(), v.GetData(), 1); err != nil {
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

	return nil
}
