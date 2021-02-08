package egressfirewalldns

import (
	//	"fmt"
	"net"
	"sync"
	"time"

	factory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	dnsobject "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/dnsobject/v1"
	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"
)

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns *util.DNS
	// name of the node
	nodeName string
	// this map holds dnsNames to the dnsEntries
	//KEYWORD can change to map[string][]net.IP??? for simplicity?
	dnsEntries map[string]*dnsEntry
	// allows to get object using the informer chace
	wf factory.NodeWatchFactory
	k  kube.Interface

	// Report change when Add operation is done
	added          chan dnsNamespace
	stopChan       chan struct{}
	controllerStop <-chan struct{}
}

type dnsEntry struct {
	// the current IP addresses the dnsName resolves to
	// NOTE: used for testing
	dnsResolves []net.IP
}

type dnsNamespace struct {
	dnsName   string
	namespace string
}

func NewEgressDNS(nodeName string, watchFactory factory.NodeWatchFactory, k kube.Interface, controllerStop <-chan struct{}) (*EgressDNS, error) {
	dnsInfo, err := util.NewDNS("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	egressDNS := &EgressDNS{
		dns:        dnsInfo,
		nodeName:   nodeName,
		dnsEntries: make(map[string]*dnsEntry),
		wf:         watchFactory,
		k:          k,

		added:          make(chan dnsNamespace, 1),
		stopChan:       make(chan struct{}),
		controllerStop: controllerStop,
	}

	return egressDNS, nil
}

func (e *EgressDNS) Add(egressfirewall *egressfirewall.EgressFirewall) error {
	//KEYWORD: don't think I need the locking?
	klog.Errorf("KEYWORD WHAT IS HAPPENING")
	e.lock.Lock()
	defer e.lock.Unlock()
	klog.Errorf("KEYWORD: HERE")

	for _, egressFirewallRule := range egressfirewall.Spec.Egress {
		if egressFirewallRule.To.DNSName != "" {
			klog.Errorf("KEYWORD: THIS IS A DNS ONE with name %s", egressFirewallRule.To.DNSName)
			if _, exists := e.dnsEntries[egressFirewallRule.To.DNSName]; !exists {
				e.dnsEntries[egressFirewallRule.To.DNSName] = &dnsEntry{}
				e.signalAdded(dnsNamespace{dnsName: egressFirewallRule.To.DNSName, namespace: egressfirewall.Namespace})
			} else {
				klog.Errorf("KEYWORD: ALREADY HERE BEFORE NOT ADDING HUMPH")
				//add the new namespace to the dnsObject
				dnsObject, err := e.wf.GetDNSObject(e.nodeName)
				if err != nil {
					return err
				}
				entry := dnsObject.Spec.DNSObjectEntries[egressFirewallRule.To.DNSName]
				entry.Namespaces = append(entry.Namespaces, egressfirewall.Namespace)
				dnsObject.Spec.DNSObjectEntries[egressFirewallRule.To.DNSName] = entry
				e.k.UpdateDNSObject(dnsObject)

			}
		} else {
			klog.Errorf("KEYWORD: THIS RULE HAS NO DNSNAME AND THE DESTINATION IS CIDR: %s", egressFirewallRule.To.CIDRSelector)
		}
	}

	return nil

}

func (e *EgressDNS) updateEntryForName(dnsNamespace dnsNamespace) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	ips := e.dns.GetIPs(dnsNamespace.dnsName)
	e.dnsEntries[dnsNamespace.dnsName].dnsResolves = ips

	klog.Errorf("KEYWORD THESE ARE THE IPS FOR %s: %s", dnsNamespace.dnsName, e.dnsEntries[dnsNamespace.dnsName].dnsResolves)
	//update the dnsObject
	dnsObject, err := e.wf.GetDNSObject(e.nodeName)
	if err != nil {
		return err
	}
	var ipStrings []string
	klog.Errorf("KEYWORD got the dnsobject %s", dnsObject.Name)
	if e.dnsEntries[dnsNamespace.dnsName] == nil {
		klog.Errorf("KEYWORD: WHY IS THIS NUL e.dnsEntries[dnsName]")
	}
	klog.Errorf("KEYWORD WHAT IS HAPPENING WITH THIS: %s", e.dnsEntries[dnsNamespace.dnsName].dnsResolves)
	for _, ip := range e.dnsEntries[dnsNamespace.dnsName].dnsResolves {
		klog.Errorf("KEYWORD CONVERTING %s to string", ip)
		ipStrings = append(ipStrings, ip.String())
	}

	if dnsObject.Spec.DNSObjectEntries == nil {
		dnsObject.Spec.DNSObjectEntries = make(map[string]dnsobject.DNSObjectEntry)
	}

	dnsObjectEntry := dnsObject.Spec.DNSObjectEntries[dnsNamespace.dnsName]
	dnsObjectEntry.IPAddresses = ipStrings
	if len(dnsNamespace.namespace) != 0 {
		inList := false
		for _, namespace := range dnsObjectEntry.Namespaces {
			if namespace == dnsNamespace.namespace {
				inList = true
				break
			}

		}
		if !inList {
			dnsObjectEntry.Namespaces = append(dnsObjectEntry.Namespaces, dnsNamespace.namespace)
		}
	}
	dnsObject.Spec.DNSObjectEntries[dnsNamespace.dnsName] = dnsObjectEntry

	e.k.UpdateDNSObject(dnsObject)

	return nil
}

func (e *EgressDNS) Update(dns string) (bool, error) {
	return e.dns.Update(dns)
}

// Run spawns a goroutine that handles updates to the dns entries for dnsNames used in
// EgressFirewalls. The loop runs after receiving one of two signals
// 1. a new dnsName has been added and a signal is sent to add the new DNS name, if an
//    EgressFirewall uses a DNS name already added by another egressFirewall the previous
//    entry is used
// 2. If the defaultInterval has run (30 min) without updating the DNS server is manually queried
func (e *EgressDNS) Run(defaultInterval time.Duration) {
	var dnsNamespace dnsNamespace
	var ttl time.Time
	var timeSet bool
	// initially the next DNS Query happens at the default interval
	durationTillNextQuery := defaultInterval
	go func() {
		for {
			// Wait for the given duration or until something gets added
			select {
			case dnsNamespace := <-e.added:
				if err := e.dns.Add(dnsNamespace.dnsName); err != nil {
					utilruntime.HandleError(err)
				}
				if err := e.updateEntryForName(dnsNamespace); err != nil {
					utilruntime.HandleError(err)
				}
				if e.dnsEntries[dnsNamespace.dnsName] == nil {
					klog.Errorf("KEYWORD: WHY IS THIS nil e.dnsEntries[dnsName]")
				} else {
					klog.Errorf("KEYWORD DUH IT ISNT e.dnsEntries[%s] = %s", dnsNamespace.dnsName, e.dnsEntries[dnsNamespace.dnsName].dnsResolves)
				}
			case <-time.After(durationTillNextQuery):
				if len(dnsNamespace.dnsName) > 0 {
					if _, err := e.Update(dnsNamespace.dnsName); err != nil {
						utilruntime.HandleError(err)
					}
					if err := e.updateEntryForName(dnsNamespace); err != nil {
						utilruntime.HandleError(err)
					}
				}
			case <-e.stopChan:
				return
			case <-e.controllerStop:
				return
			}
			/*
				klog.Errorf("KEYWORD WHAT IS THE DNSNAME: %s", dnsName)

				//update the dnsObject
				dnsObject, err := e.wf.GetDNSObject(e.nodeName)
				if err != nil {
					utilruntime.HandleError(err)
				}
				var ipStrings []string
				klog.Errorf("KEYWORD got the dnsobject %s", dnsObject.Name)
				if e.dnsEntries[dnsName] == nil {
					klog.Errorf("KEYWORD: WHY IS THIS NUL e.dnsEntries[dnsName]")
				}
				klog.Errorf("KEYWORD WHAT IS HAPPENING WITH THIS: %s", e.dnsEntries[dnsName].dnsResolves)
				for _, ip := range e.dnsEntries[dnsName].dnsResolves {
					klog.Errorf("KEYWORD CONVERTING %s to string", ip)
					ipStrings = append(ipStrings, ip.String())
				}

				dnsObject.Spec.DNSObjectEntries[e.nodeName].NodeIPEntries[dnsName] = ipStrings
				e.k.UpdateDNSObject(dnsObject)
			*/
			// before waiting on the signals get the next time this thread needs to wake up
			ttl, dnsNamespace.dnsName, timeSet = e.dns.GetNextQueryTime()
			dnsNamespace.namespace = ""
			if time.Until(ttl) > defaultInterval || !timeSet {
				durationTillNextQuery = defaultInterval
			} else {
				durationTillNextQuery = time.Until(ttl)
			}
		}
	}()

}

/*
func (e *EgressDNS) updateEntryForName(dnsName string) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	ips := e.dns.GetIPs(dnsName)

	fmt.Printf("IPs from %s are %s", e.nodeName, ips)
	e.dnsEntries[dnsName].dnsResolves = ips

	return nil
}
*/
func (e *EgressDNS) Shutdown() {
	close(e.stopChan)
}

func (e *EgressDNS) signalAdded(dnsNS dnsNamespace) {
	e.added <- dnsNS
}
