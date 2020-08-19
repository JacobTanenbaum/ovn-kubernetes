package util

import (
	"github.com/miekg/dns"
)

type DNSOps interface {
	ClientConfigFromFile(resolvconf string) (*dns.ClientConfig, error)
	Fqdn(s string) string
}

type defaultDNSOps struct{}

var dnsOps DNSOps = &defaultDNSOps{}

func SetDNSLibOpsMockInst(mockInst DNSOps) {
	dnsOps = mockInst
}
func GetDNSLibOps() DNSOps {
	return dnsOps
}

func (defaultDNSOps) ClientConfigFromFile(resolveconf string) (*dns.ClientConfig, error) {
	return dns.ClientConfigFromFile(resolveconf)
}

func (defaultDNSOps) Fqdn(s string) string {
	return dns.Fqdn(s)
}
