package util

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

const (
	// defaultTTL is used if an invalid or zero TTL is provided.
	defaultTTL = 30 * time.Minute
)

type dnsValue struct {
	// All IPv4 addresses for a given domain name
	ips []net.IP
	// Time-to-live value from non-authoritative/cached name server for the domain
	ttl time.Duration
	// Holds (last dns lookup time + ttl), tells when to refresh IPs next time
	nextQueryTime time.Time
}

type DNS struct {
	// Protects dnsMap operations
	lock sync.Mutex
	// Holds dns name and its corresponding information
	dnsMap map[string]dnsValue

	// DNS resolvers
	nameservers []string
	// DNS port
	port string
}

func NewDNS(resolverConfigFile string) (*DNS, error) {
	config, err := dnsOps.ClientConfigFromFile(resolverConfigFile)
	if err != nil || config == nil {
		return nil, fmt.Errorf("cannot initialize the resolver: %v", err)
	}

	return &DNS{
		dnsMap:      map[string]dnsValue{},
		nameservers: filterIPv4Servers(config.Servers),
		port:        config.Port,
	}, nil
}

func (d *DNS) Size() int {
	d.lock.Lock()
	defer d.lock.Unlock()

	return len(d.dnsMap)
}

func (d *DNS) Get(dns string) dnsValue {
	d.lock.Lock()
	defer d.lock.Unlock()

	data := dnsValue{}
	if res, ok := d.dnsMap[dns]; ok {
		data.ips = make([]net.IP, len(res.ips))
		copy(data.ips, res.ips)
		data.ttl = res.ttl
		data.nextQueryTime = res.nextQueryTime
	}
	return data
}

func (d *DNS) GetIPs(dns string) []net.IP {
	d.lock.Lock()
	defer d.lock.Unlock()

	data := dnsValue{}
	if res, ok := d.dnsMap[dns]; ok {
		data.ips = make([]net.IP, len(res.ips))
		copy(data.ips, res.ips)
		data.ttl = res.ttl
		data.nextQueryTime = res.nextQueryTime
	}
	return data.ips
}

func (d *DNS) Add(dns string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.dnsMap[dns] = dnsValue{}
	_, err := d.updateOne(dns)
	if err != nil {
		delete(d.dnsMap, dns)
	}
	return err
}

func (d *DNS) Delete(dns string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	delete(d.dnsMap, dns)
}

func (d *DNS) Update(dnsName string) (bool, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.updateOne(dnsName)
}

func (d *DNS) updateOne(dns string) (bool, error) {
	res, ok := d.dnsMap[dns]
	if !ok {
		// Should not happen, all operations on dnsMap are synchronized by d.lock
		return false, fmt.Errorf("DNS value not found in dnsMap for domain: %q", dns)
	}

	ips, ttl, err := d.getIPsAndMinTTL(dns)
	if err != nil {
		res.nextQueryTime = time.Now().Add(defaultTTL)
		d.dnsMap[dns] = res
		return false, err
	}

	changed := false
	if !ipsEqual(res.ips, ips) {
		changed = true
	}
	res.ips = ips
	res.ttl = ttl
	res.nextQueryTime = time.Now().Add(res.ttl)
	d.dnsMap[dns] = res
	return changed, nil
}

func (d *DNS) getIPsAndMinTTL(domain string) ([]net.IP, time.Duration, error) {
	ips := []net.IP{}
	ttlSet := false
	var ttlSeconds uint32
	var minTTL uint32
	var recordTypes []uint16

	if config.IPv4Mode {
		recordTypes = append(recordTypes, dns.TypeA)
	}
	if config.IPv6Mode {
		recordTypes = append(recordTypes, dns.TypeAAAA)
	}

	for _, recordType := range recordTypes {
		for _, server := range d.nameservers {
			msg := new(dns.Msg)
			dnsOps.SetQuestion(msg, dnsOps.Fqdn(domain), recordType)

			dialServer := server
			if _, _, err := net.SplitHostPort(server); err != nil {
				dialServer = net.JoinHostPort(server, d.port)
			}
			c := new(dns.Client)
			c.Timeout = 5 * time.Second
			in, _, err := dnsOps.Exchange(c, msg, dialServer)
			if err != nil {
				return nil, defaultTTL, err
			}
			if in != nil && in.Rcode != dns.RcodeSuccess {
				return nil, defaultTTL, fmt.Errorf("failed to get a valid answer: %v", in)
			}

			if in != nil && len(in.Answer) > 0 {
				for _, a := range in.Answer {
					if !ttlSet || a.Header().Ttl < ttlSeconds {
						ttlSeconds = a.Header().Ttl
						ttlSet = true
						if minTTL == 0 {
							minTTL = ttlSeconds
						}
					}

					switch t := a.(type) {
					case *dns.A:
						ips = append(ips, t.A)
					case *dns.AAAA:
						ips = append(ips, t.AAAA)
					}
				}
				if ttlSeconds < minTTL {
					minTTL = ttlSeconds
				}
			}
		}
	}

	if !ttlSet || (len(ips) == 0) {
		return nil, defaultTTL, fmt.Errorf("IPv4 or IPv6 addr not found for domain: %q, nameservers: %v", domain, d.nameservers)
	}

	ttl, err := time.ParseDuration(fmt.Sprintf("%ds", minTTL))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid TTL value for domain: %q, err: %v, defaulting ttl=%s", domain, err, defaultTTL.String()))
		ttl = defaultTTL
	}
	if ttl == 0 {
		ttl = defaultTTL
	}

	return removeDuplicateIPs(ips), ttl, nil
}

func (d *DNS) GetNextQueryTime() (time.Time, string, bool) {
	d.lock.Lock()
	defer d.lock.Unlock()

	timeSet := false
	var minTime time.Time
	var dns string

	for dnsName, res := range d.dnsMap {
		if !timeSet || res.nextQueryTime.Before(minTime) {
			timeSet = true
			minTime = res.nextQueryTime
			dns = dnsName
		}
	}
	return minTime, dns, timeSet
}

func ipsEqual(oldips, newips []net.IP) bool {
	if len(oldips) != len(newips) {
		return false
	}

	for _, oldip := range oldips {
		found := false
		for _, newip := range newips {
			if oldip.Equal(newip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func filterIPv4Servers(servers []string) []string {
	ipv4Servers := []string{}
	for _, server := range servers {

		ipString := server
		if host, _, err := net.SplitHostPort(server); err == nil {
			ipString = host
		}

		if ip := net.ParseIP(ipString); ip != nil {
			if ip.To4() != nil {
				ipv4Servers = append(ipv4Servers, server)
			}
		}
	}

	return ipv4Servers
}

func removeDuplicateIPs(ips []net.IP) []net.IP {
	ipSet := sets.NewString()
	for _, ip := range ips {
		ipSet.Insert(ip.String())
	}

	uniqueIPs := []net.IP{}
	for _, str := range ipSet.List() {
		ip := net.ParseIP(str)
		if ip != nil {
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	return uniqueIPs
}
