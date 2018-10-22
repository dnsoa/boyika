package main

import (
	"errors"
	"net"
	"sync"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginsAction int

const (
	PluginsActionNone    = 0
	PluginsActionForward = 1
	PluginsActionDrop    = 2
	PluginsActionReject  = 3
	PluginsActionSynth   = 4
)

type PluginsGlobals struct {
	sync.RWMutex
	queryPlugins    *[]Plugin
	responsePlugins *[]Plugin
}

type PluginsState struct {
	action                 PluginsAction
	originalMaxPayloadSize int
	maxPayloadSize         int
	clientProto            string
	clientAddr             *net.Addr
	synthResponse          *dns.Msg
	dnssec                 bool
	cacheSize              int
	cacheNegMinTTL         uint32
	cacheNegMaxTTL         uint32
	cacheMinTTL            uint32
	cacheMaxTTL            uint32
	questionMsg            *dns.Msg
}

func InitPluginsGlobals(pluginsGlobals *PluginsGlobals, proxy *Proxy) error {
	queryPlugins := &[]Plugin{}
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginCache)))
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginHosts)))
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockName)))
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginDoh)))
	//*queryPlugins = append(*queryPlugins, Plugin(new(PluginCloudFlare)))
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginForward)))

	responsePlugins := &[]Plugin{}
	*responsePlugins = append(*responsePlugins, Plugin(new(PluginBlockIP)))
	*responsePlugins = append(*responsePlugins, Plugin(new(PluginCacheResponse)))

	for _, plugin := range *queryPlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	for _, plugin := range *responsePlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	(*pluginsGlobals).queryPlugins = queryPlugins
	(*pluginsGlobals).responsePlugins = responsePlugins
	return nil
}

type Plugin interface {
	Name() string
	Description() string
	Init(proxy *Proxy) error
	Drop() error
	Reload() error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proxy *Proxy, clientProto string, clientAddr *net.Addr) PluginsState {
	return PluginsState{
		action:         PluginsActionForward,
		maxPayloadSize: MaxDNSUDPPacketSize,
		clientProto:    clientProto,
		clientAddr:     clientAddr,
		questionMsg:    nil,
	}
}

func (pluginsState *PluginsState) ApplyQueryPlugins(pluginsGlobals *PluginsGlobals, packet []byte) ([]byte, error) {
	if len(*pluginsGlobals.queryPlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	if len(msg.Question) > 1 {
		return packet, errors.New("Unexpected number of questions")
	}
	pluginsState.questionMsg = &msg
	pluginsGlobals.RLock()
	for _, plugin := range *pluginsGlobals.queryPlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsGlobals.RUnlock()
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action == PluginsActionReject {
			synth, err := RefusedResponseFromMessage(&msg)
			if err != nil {
				return nil, err
			}
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	pluginsGlobals.RUnlock()
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

func (pluginsState *PluginsState) ApplyResponsePlugins(pluginsGlobals *PluginsGlobals, packet []byte, ttl *uint32) ([]byte, error) {
	if len(*pluginsGlobals.responsePlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		if len(packet) >= MinDNSPacketSize && HasTCFlag(packet) {
			err = nil
		}
		dlog.Errorf("ERR :%s ", err)
		return packet, err
	}
	pluginsGlobals.RLock()
	for _, plugin := range *pluginsGlobals.responsePlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsGlobals.RUnlock()
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action == PluginsActionReject {
			synth, err := RefusedResponseFromMessage(&msg)
			if err != nil {
				return nil, err
			}
			msg = *synth
			dlog.Infof("Blocking [%s]", synth.Question[0].Name)
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	pluginsGlobals.RUnlock()
	if ttl != nil {
		setMaxTTL(&msg, *ttl)
	}
	packet2, err := msg.PackBuffer(packet)
	if err != nil {

		return packet, err
	}
	return packet2, nil
}
