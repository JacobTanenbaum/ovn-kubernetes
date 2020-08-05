package util

import (
	"net"
	"sync"
	"time"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
)

type EgressDNSUpdate struct {
	UID       ktypes.UID
	Namespace string
}

type EgressDNSUpdates []EgressDNSUpdate

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns *DNS
	// this map holds which DNS names are in what policy objects
	dnsNamesToPolicies map[string]sets.String
	// Maintain namespaces for each policy to avoid querying etcd in syncEgressDNSPolicyRules()
	namespaces map[ktypes.UID]string

	// map of namespace to map of dnsName to ACL information
	ACLs map[string]map[string]*ACLInformation
	// map of dnsNames to all namespaces that they appear in
	DNSInNamespace map[string]map[string]struct{}

	// Report change when Add operation is done
	added chan bool

	// Report changes when there are dns updates
	Updates chan EgressDNSUpdates
}

func NewEgressDNS() (*EgressDNS, error) {
	dnsInfo, err := NewDNS("/etc/resolv.conf")
	if err != nil {
		utilruntime.HandleError(err)
		return nil, err
	}
	return &EgressDNS{
		dns:                dnsInfo,
		dnsNamesToPolicies: map[string]sets.String{},
		namespaces:         map[ktypes.UID]string{},

		ACLs:           make(map[string]map[string]*ACLInformation),
		DNSInNamespace: make(map[string]map[string]struct{}),

		added:   make(chan bool),
		Updates: make(chan EgressDNSUpdates),
	}, nil
}

type ACLInformation struct {
	//dnsName     string
	ipAddresses      []net.IP
	priority         int
	action           string
	hashedAddressSet string
}

func newACLInformation(priority int, action, hashedAddressSet string) *ACLInformation {
	return &ACLInformation{
		priority:         priority,
		action:           action,
		hashedAddressSet: hashedAddressSet,
	}

}

func (e *EgressDNS) Addold(policy egressfirewallapi.EgressFirewall) {
	e.lock.Lock()
	defer e.lock.Unlock()

	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if uids, exists := e.dnsNamesToPolicies[rule.To.DNSName]; !exists {
				e.dnsNamesToPolicies[rule.To.DNSName] = sets.NewString(string(policy.UID))
				//only call Add if the dnsName doesn't exist in the dnsNamesToPolicies
				if err := e.dns.Add(rule.To.DNSName); err != nil {
					utilruntime.HandleError(err)
				}
				e.signalAdded()
			} else {
				e.dnsNamesToPolicies[rule.To.DNSName] = uids.Insert(string(policy.UID))
			}
		}
	}
	e.namespaces[policy.UID] = policy.Namespace
}

func (e *EgressDNS) Add(namespace, dnsName, action, hashedAddressSet string, priority int) {
	e.lock.Lock()
	defer e.lock.Unlock()

	if _, exists := e.DNSInNamespace[dnsName]; !exists {
		e.DNSInNamespace[dnsName] = make(map[string]struct{})
		e.DNSInNamespace[dnsName][namespace] = struct{}{}
		//only call Add if the dnsName doesn't exist in DNSInNamespace
		if err := e.dns.Add(dnsName); err != nil {
			utilruntime.HandleError(err)
		}
		e.signalAdded()
	} else {
		e.DNSInNamespace[dnsName][namespace] = struct{}{}

	}
	if e.ACLs[namespace] == nil {
		e.ACLs[namespace] = make(map[string]*ACLInformation)
	}
	e.ACLs[namespace][dnsName] = newACLInformation(priority, action, hashedAddressSet)
	e.ACLs[namespace][dnsName].ipAddresses = e.GetIPs(dnsName)

}

/*
func (e *EgressDNS) Add(dnsName, namespace string, policyUID ktypes.UID) {
	if uids, exists := e.dnsNamesToPolicies[dnsName]; !exists {
		e.dnsNamesToPolicies[dnsName] = sets.NewString(string(policyUID))
		if err := e.dns.Add(dnsName); err != nil {
			utilruntime.HandleError(err)
		}
		e.signalAdded()
	} else {
		e.dnsNamesToPolicies[dnsName] = uids.Insert(string(policyUID))
	}
	e.namespaces[policyUID] = namespace

}
*/
func (e *EgressDNS) Delete(policy egressfirewallapi.EgressFirewall) {
	e.lock.Lock()
	defer e.lock.Unlock()
	//delete the entry from the dnsNames to UIDs map for each rule in the policy
	//if the slice is empty at this point, delete the entry from the dns object too
	//also remove the policy entry from the namespaces map.
	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if uids, ok := e.dnsNamesToPolicies[rule.To.DNSName]; ok {
				uids.Delete(string(policy.UID))
				if uids.Len() == 0 {
					e.dns.Delete(rule.To.DNSName)
					delete(e.dnsNamesToPolicies, rule.To.DNSName)
				} else {
					e.dnsNamesToPolicies[rule.To.DNSName] = uids
				}
			}
		}
	}

	if _, ok := e.namespaces[policy.UID]; ok {
		delete(e.namespaces, policy.UID)
	}
}

func (e *EgressDNS) Update(dns string) (bool, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	return e.dns.Update(dns)
}

func (e *EgressDNS) Sync() {
	klog.Errorf("KEYWORD - HERE RIGHT NOW")
	var duration time.Duration
	for {
		tm, dnsName, updates, ok := e.GetNextQueryTime()
		if !ok {
			klog.Errorf("KEYWORD - IN 30")
			duration = 30 * time.Minute
		} else {
			klog.Errorf("KEYWORD - DOING SOMETHING")
			now := time.Now()
			if tm.After(now) {
				klog.Errorf("KEYWORD - SOME DURATION")
				// Item needs to wait for this duration before it can be processed
				duration = tm.Sub(now)
			} else {
				klog.Errorf("KEYWORD - RIGHT NOW")
				changed, err := e.Update(dnsName)
				if err != nil {
					utilruntime.HandleError(err)
				}

				if changed {
					e.Updates <- updates
				}
				continue
			}
		}

		// Wait for the given duration or till something got added
		select {
		case <-e.added:
		case <-time.After(duration):
		}
	}
}

func (e *EgressDNS) GetNextQueryTime() (time.Time, string, []EgressDNSUpdate, bool) {
	klog.Errorf("KEYWORD - IN NEXTQUERYTIME()")
	e.lock.Lock()
	defer e.lock.Unlock()
	policyUpdates := make([]EgressDNSUpdate, 0)
	tm, dnsName, timeSet := e.dns.GetNextQueryTime()
	if !timeSet {
		klog.Errorf("KEYWORD - RETURNING WITHOUT TIMESET")
		return tm, dnsName, nil, timeSet
	}
	/*
		if uids, exists := e.dnsNamesToPolicies[dnsName]; exists {
			for uid := range uids {
				policyUpdates = append(policyUpdates, EgressDNSUpdate{ktypes.UID(uid), e.namespaces[ktypes.UID(uid)]})
			}
	*/
	if namespaces, exists := e.DNSInNamespace[dnsName]; exists {

		klog.Errorf("KEYWORD DOING THE THING - %s", namespaces)
	} else {
		klog.V(5).Infof("Didn't find any entry for dns name: %s in the dns map.", dnsName)
	}
	klog.Errorf("KEYWORD Releaseing LOCK GETNEXTQUERYTIME()")
	return tm, dnsName, policyUpdates, timeSet
}

func (e *EgressDNS) GetIPs(dnsName string) []net.IP {
	e.lock.Lock()
	defer e.lock.Unlock()
	return e.dns.Get(dnsName).ips

}

func (e *EgressDNS) GetNetCIDRs(dnsName string) []net.IPNet {
	cidrs := []net.IPNet{}
	for _, ip := range e.GetIPs(dnsName) {
		// IPv4 CIDR
		cidrs = append(cidrs, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
	}
	return cidrs
}

func (e *EgressDNS) signalAdded() {
	// Non-blocking op
	select {
	case e.added <- true:
	default:
	}
}
