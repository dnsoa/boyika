package main

import (
	"math/rand"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginForward struct {
	servers []string
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	plugin.servers = []string{"8.8.8.8:53"}
	return nil
}

func (plugin *PluginForward) Drop() error {
	return nil
}

func (plugin *PluginForward) Reload() error {
	return nil
}

func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	if len(plugin.servers) == 0 {
		return nil
	}
	server := plugin.servers[rand.Intn(len(plugin.servers))]

	respMsg, err := dns.Exchange(msg, server)
	if err != nil {
		dlog.Errorf("Error exchange server[%s]: %s", server, err)
		return err
	}
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	return nil
}
