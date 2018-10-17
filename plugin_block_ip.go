package main

import (
	"net"
	"strings"

	"github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginBlockIP struct {
	blockedPrefixes *iradix.Tree
	blockedIPs      map[string]interface{}
}

func (plugin *PluginBlockIP) Name() string {
	return "block_ip"
}

func (plugin *PluginBlockIP) Description() string {
	return "Block responses containing specific IP addresses"
}

func (plugin *PluginBlockIP) Init(proxy *Proxy) error {
	dlog.Notice("Loading the set of IP blocking rules")
	plugin.blockedPrefixes = iradix.New()
	plugin.blockedIPs = make(map[string]interface{})
	for _, vv := range proxy.db.GetBlockIp() {
		ip := net.ParseIP(vv)
		trailingStar := strings.HasSuffix(vv, "*")
		if len(vv) < 2 || (ip != nil && trailingStar) {
			dlog.Errorf("Suspicious IP blocking rule [%s]", vv)
			continue
		}
		if trailingStar {
			vv = vv[:len(vv)-1]
		}
		if strings.HasSuffix(vv, ":") || strings.HasSuffix(vv, ".") {
			vv = vv[:len(vv)-1]
		}
		if len(vv) == 0 {
			continue
		}
		if strings.Contains(vv, "*") {
			dlog.Errorf("Invalid rule: [%s] - wildcards can only be used as a suffix", vv)
			continue
		}
		vv = strings.ToLower(vv)
		if trailingStar {
			plugin.blockedPrefixes, _, _ = plugin.blockedPrefixes.Insert([]byte(vv), 0)
		} else {
			plugin.blockedIPs[vv] = true
		}
	}

	return nil
}

func (plugin *PluginBlockIP) Drop() error {
	return nil
}

func (plugin *PluginBlockIP) Reload() error {
	return nil
}

func (plugin *PluginBlockIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}
	reject, reason, ipStr := false, "", ""
	for _, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA && Rrtype != dns.TypeAAAA) {
			continue
		}
		if Rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.String()
		} else if Rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.String() // IPv4-mapped IPv6 addresses are converted to IPv4
		}
		if _, found := plugin.blockedIPs[ipStr]; found {
			reject, reason = true, ipStr
			break
		}
		match, _, found := plugin.blockedPrefixes.Root().LongestPrefix([]byte(ipStr))
		if found {
			if len(match) == len(ipStr) || (ipStr[len(match)] == '.' || ipStr[len(match)] == ':') {
				reject, reason = true, string(match)+"*"
				break
			}
		}
	}
	if reject {
		dlog.Debugf("block ip : %s", reason)
		pluginsState.action = PluginsActionReject
	}
	return nil
}
