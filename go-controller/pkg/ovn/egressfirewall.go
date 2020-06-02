package ovn

import (
	"fmt"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	"k8s.io/klog"
)

/*
*****NOTES*****
addPodToNamespace already adds the address of the pod to the address set


Since the rules are processed from top to bottom that means that some can overlap and while the whitelisting
of all internal ip addresses needs to be highest all subsequent rules need to be of a different priority level becuase
they can overlap and the first one that is defined needs to be followed


want to use toLport

Since I have to enforce an order if an egressFirewall Object is modified I need to delete and recreate it.
*/

const (
	//	toLport = "to-lport"
	//fromLport = "from-lport" -- use this one
	//default priority to whitelist internal traffic
	defaultWhitelistPriority = 2000
)

//could use the namespacePolicy?...KEYWORD

type egressFirewall struct {
	sync.Mutex  //not sure if needed
	name        string
	namespace   string
	egressRules []egressFirewallRule
}

type egressFirewallRule struct {
	id           int
	access       string        //ALLOW or DENY
	ports        []port        //the ports that this rule applies to
	destinations []destination //either a DNS name or cidr selector

}

// KEYWORD: can use port policy struct from policy.go?
type port struct {
	Protocol string //UDP, TCP, SCTP
	Port     int32
}

type destination struct { //could make it all a CIDR selector and resolve DNS namespace here KEYWORD
	dnsName      string
	CIDRSelector string
}

func (oc *Controller) addEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) {
	klog.Infof("Adding egress Firewall %s in namesapce %s", egressFirewall.Name, egressFirewall.Namespace)
	nsInfo, err := oc.waitForNamespaceLocked(egressFirewall.Namespace)
	if err != nil {
		klog.Errorf("failed to wait for namespace %s event (%v)",
			egressFirewall.Namespace, err)
	}
	defer nsInfo.Unlock() //KEYWORD: do I need to defer or can I Unlock sooner ...

	for _, portName := range nsInfo.addressSet {
		if portInfo, err := oc.logicalPortCache.get(portName); err != nil {
			klog.Errorf(err.Error())
		} else if err := addToPortGroup(hashedPortGroup(egressFirewall.Namespace), portInfo); err != nil {
			klog.Warningf("failed to add port %s to port group ACL: %v", portName, err)
		}
	}

	if nsInfo.egressFirewall {
		klog.Errorf("Attempting to add egressFirewall %s to namespace %s when it already has an egressFirewall",
			egressFirewall.Name, egressFirewall.Namespace)
		return
	}
	nsInfo.egressFirewall = true

	// add the port_group
	err = nsInfo.updateNamespacePortGroup(egressFirewall.Namespace)
	if err != nil {
		nsInfo.egressFirewall = false
		return
	}
	priority := defaultWhitelistPriority
	//whitelist internal traffic
	// config.Kubernetes.ServiceCIDRS
	for _, serviceSubnet := range config.Kubernetes.ServiceCIDRs {
		//whitelist the serviceCIDRs
		addACLAndRule(nsInfo.portGroupUUID, egressFirewall.Namespace, serviceSubnet.String(), "allow", priority)
		priority++
	}
	//config.Default.ClusterSubnets
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		addACLAndRule(nsInfo.portGroupUUID, egressFirewall.Namespace, clusterSubnet.CIDR.String(), "allow", priority)
		priority++
	}

	//block all traffic
	addACLAndRule(nsInfo.portGroupUUID, egressFirewall.Namespace, "0.0.0.0/0", "drop", priority)
	priority++

}

func (oc *Controller) updateEgressFirewall(oldEgressFirewall, newEgressFirewall *egressfirewallapi.EgressFirewall) {
	//probably just going to delete and re-add but for now look into this
}

func (oc *Controller) deleteEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) {
	klog.Infof("Deleting egress Firewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)
	nsInfo := oc.getNamespaceLocked(egressFirewall.Namespace)
	if nsInfo == nil {
		return
	}

	//remove the ranges from the struct...
	//remove whitelist
}

// add port group and rule
func addACLAndRule(portGroupUUID, portGroupName, ipCIDR, action string, priority int) error {
	match := fmt.Sprintf("match=\"ip4.dst == %s && inport == @%s\"", ipCIDR, portGroupUUID)

	_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%d", priority),
		fmt.Sprintf("direction=%s", fromLport), match, "action="+action,
		fmt.Sprintf("external-ids:KEYWORD=test"),
		"--", "add", "port_group", portGroupUUID,
		"acls", "@acl")
	if err != nil {
		klog.Errorf(" error executing create ACL command, stderr: %q, %+v",
			stderr, err)
		return err
	}

	return nil

}
