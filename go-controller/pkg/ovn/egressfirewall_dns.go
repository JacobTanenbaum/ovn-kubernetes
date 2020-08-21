package ovn

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
)

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns *util.DNS
	// this map holds dnsNames to the dnsEntries
	dnsEntries map[string]*dnsEntry
	// allows for the creation of addresssets
	addressSetFactory AddressSetFactory

	// Report change when Add operation is done
	added          chan bool
	stopChan       chan struct{}
	controllerStop <-chan struct{}
}

type dnsEntry struct {
	//this map holds all the namespaces that a dnsName appears in
	namespaces map[string]struct{}
	// the current IP addresses the dnsName resolves to
	dnsResolves []net.IP
	// the addressSet that contains the current IPs
	dnsAddressSet AddressSet
}

func NewEgressDNS(addressSetFactory AddressSetFactory, controllerStop <-chan struct{}) (*EgressDNS, error) {
	klog.Errorf("KEYWORD IN NEWEGRESSDNS")
	dnsInfo, err := util.NewDNS("/etc/resolv.conf")
	klog.Errorf("KEYWORD MOCKED THE FIRST THING")
	if err != nil {
		utilruntime.HandleError(err)
		return nil, err
	}

	egressDNS := &EgressDNS{
		dns:               dnsInfo,
		dnsEntries:        make(map[string]*dnsEntry),
		addressSetFactory: addressSetFactory,

		added:          make(chan bool),
		stopChan:       make(chan struct{}),
		controllerStop: controllerStop,
	}

	go utilwait.Until(egressDNS.Sync, 0, egressDNS.stopChan)

	return egressDNS, nil
}

func (e *EgressDNS) Add(namespace, dnsName string) (AddressSet, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	if _, exists := e.dnsEntries[dnsName]; !exists {
		var err error
		dnsEntry := dnsEntry{
			namespaces: make(map[string]struct{}),
		}
		dnsEntry.dnsAddressSet, err = e.addressSetFactory.NewAddressSet(dnsName, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot create addressSet for %s: %v", dnsName, err)
		}
		e.dnsEntries[dnsName] = &dnsEntry
		//only call Add if the dnsName doesn't exist in dnsEntries
		if err := e.dns.Add(dnsName); err != nil {
			utilruntime.HandleError(err)
		}
		unsorted := e.dns.GetIPs(dnsName)
		e.dnsEntries[dnsName].dnsResolves = sortIPs(unsorted)
		err = e.dnsEntries[dnsName].dnsAddressSet.AddIPs(e.dnsEntries[dnsName].dnsResolves)
		if err != nil {
			return nil, fmt.Errorf("cannot add IPs to EgressFirewalls AddressSet: %s - %v", dnsName, err)
		}
		e.signalAdded()
	}
	e.dnsEntries[dnsName].namespaces[namespace] = struct{}{}
	return e.dnsEntries[dnsName].dnsAddressSet, nil

}

func (e *EgressDNS) Delete(namespace string) bool {
	e.lock.Lock()
	defer e.lock.Unlock()

	// go through all dnsNames for namespaces
	for dnsName, dnsEntry := range e.dnsEntries {
		// delete the dnsEntry
		delete(dnsEntry.namespaces, namespace)
		if len(dnsEntry.namespaces) == 0 {
			// the dnsEntry appears in no other namespace so delete the address_set
			err := dnsEntry.dnsAddressSet.Destroy()
			if err != nil {
				klog.Errorf("Error deleteing EgressFirewall AddressSet for dnsName: %s %v", dnsName, err)
			}
			// the dnsEntry is no longer needed because nothing referances it delete it
			delete(e.dnsEntries, dnsName)
		}
	}
	return len(e.dnsEntries) == 0
}

func (e *EgressDNS) Update(dns string) (bool, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	return e.dns.Update(dns)
}

func (e *EgressDNS) Sync() {
	var duration time.Duration
	for {
		tm, dnsName, ok := e.GetNextQueryTime()
		if !ok {
			duration = 30 * time.Minute
		} else {
			now := time.Now()
			if tm.After(now) {
				duration = tm.Sub(now)
			} else {
				_, err := e.Update(dnsName)
				if err != nil {
					utilruntime.HandleError(err)
				}

				sortedIPs := sortIPs(e.dns.GetIPs(dnsName))
				if !reflect.DeepEqual(e.dnsEntries[dnsName].dnsResolves, sortedIPs) {
					//flush the old ips from the addressSets
					addressSet := e.dnsEntries[dnsName].dnsAddressSet
					err := addressSet.DeleteIPs(e.dnsEntries[dnsName].dnsResolves)
					if err != nil {
						klog.Errorf("Cannot delete IPs from EgressFirewall AddressSet: %s - %v", dnsName, err)
					}
					err = addressSet.AddIPs(sortedIPs)
					if err != nil {
						klog.Errorf("Cannot add IPs from EgressFirewall AddressSet: %s - %v", dnsName, err)
					}
					e.dnsEntries[dnsName].dnsResolves = sortedIPs
				}
				continue
			}
		}

		// Wait for the given duration or till something got added
		select {
		case <-e.controllerStop:
			return
		case <-e.stopChan:
			return
		case <-e.added:
		case <-time.After(duration):
		}
	}
}

func (e *EgressDNS) GetNextQueryTime() (time.Time, string, bool) {
	e.lock.Lock()
	defer e.lock.Unlock()
	tm, dnsName, timeSet := e.dns.GetNextQueryTime()

	return tm, dnsName, timeSet
}

func (e *EgressDNS) GetIPs(dnsName string) []net.IP {
	e.lock.Lock()
	defer e.lock.Unlock()
	return e.dns.GetIPs(dnsName)

}

func (e *EgressDNS) signalAdded() {
	// Non-blocking op
	select {
	case e.added <- true:
	default:
	}
}

func sortIPs(IPs []net.IP) []net.IP {

	sort.Slice(IPs, func(i, j int) bool {
		return bytes.Compare(IPs[i], IPs[j]) < 0
	})
	return IPs
}
