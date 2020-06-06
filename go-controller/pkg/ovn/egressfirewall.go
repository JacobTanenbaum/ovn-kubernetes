package ovn

import (
	"fmt"
	"strings"
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
	egressRules []*egressFirewallRule
}

type egressFirewallRule struct {
	id           int
	access       egressfirewallapi.EgressFirewallRuleType //ALLOW or DENY
	ports        []*port                                  //the ports that this rule applies to
	destinations []*destination                           //either a DNS name or cidr selector
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

func newEgressFirewall(egressFirewallPolicy *egressfirewallapi.EgressFirewall) *egressFirewall {
	ef := &egressFirewall{
		name:        egressFirewallPolicy.Name,
		namespace:   egressFirewallPolicy.Namespace,
		egressRules: make([]*egressFirewallRule, 0),
	}
	return ef
}

func newEgressFirewallRule(rawEgressFirewallRule egressfirewallapi.EgressFirewallRule, id int) *egressFirewallRule {
	efr := &egressFirewallRule{
		id:           id,
		access:       rawEgressFirewallRule.Type,
		ports:        make([]*port, 0),
		destinations: make([]*destination, 0),
	}

	return efr
}

func (oc *Controller) addEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) {
	klog.Infof("Adding egress Firewall %s in namesapce %s", egressFirewall.Name, egressFirewall.Namespace)
	nsInfo, err := oc.waitForNamespaceLocked(egressFirewall.Namespace)
	if err != nil {
		klog.Errorf("failed to wait for namespace %s event (%v)",
			egressFirewall.Namespace, err)
	}
	defer nsInfo.Unlock() //KEYWORD: do I need to defer or can I Unlock sooner ...

	if nsInfo.egressFirewall {
		klog.Errorf("Attempting to add egressFirewall %s to namespace %s when it already has an egressFirewall",
			egressFirewall.Name, egressFirewall.Namespace)
		return
	}

	ef := newEgressFirewall(egressFirewall)
	nsInfo.egressFirewallPolicy = ef
	//lock the newgressFirewall and unlock nsInfo
	for i, egressFirewallRule := range egressFirewall.Spec.Rules {
		//process Rules into egressFirewallRules for egressFirewall struct
		newEgressFirewallRule(egressFirewallRule, i)

	}

	// TODO make a function that takes an egressFirewall struct and adds all the ACLs in it...
	existingNodes, err := oc.kube.GetNodes()
	if err != nil {
		klog.Errorf("KEYWORD: UNABLE TO GET NODES")
	}
	for _, node := range existingNodes.Items {

		joinSwitch := joinSwitch(node.Name)

		priority := defaultWhitelistPriority
		//whitelist internal traffic
		// config.Kubernetes.ServiceCIDRS
		for _, serviceSubnet := range config.Kubernetes.ServiceCIDRs {
			//whitelist the serviceCIDRs
			addACLAndRule(joinSwitch, egressFirewall.Namespace, nsInfo.addressSet.GetHashName(), serviceSubnet.String(), "allow", priority)
			priority++
		}
		//config.Default.ClusterSubnets
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			addACLAndRule(joinSwitch, egressFirewall.Namespace, nsInfo.addressSet.GetHashName(), clusterSubnet.CIDR.String(), "allow", priority)
			priority++
		}

		//block all traffic
		addACLAndRule(joinSwitch, egressFirewall.Namespace, nsInfo.addressSet.GetHashName(), "0.0.0.0/0", "drop", priority)
		priority++
	}

}

func (oc *Controller) updateEgressFirewall(oldEgressFirewall, newEgressFirewall *egressfirewallapi.EgressFirewall) {
	//probably just going to delete and re-add but for now look into this
}

func (oc *Controller) deleteEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) {
	klog.Infof("Deleting egress Firewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)

	nsInfo, err := oc.waitForNamespaceLocked(egressFirewall.Namespace)
	if err != nil {
		klog.Errorf("failed to wait for namespace %s event (%v)",
			egressFirewall.Namespace, err)
	}
	defer nsInfo.Unlock() //KEYWORD: do I need to defer or can I Unlock sooner ...
	nsInfo.egressFirewall = false

	stdout, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:egressFirewall=%s", egressFirewall.Namespace))
	if err != nil {
		klog.Errorf(" error executing create ACL command, stderr: %q, %+v", stderr, err)
	}
	klog.Errorf("KEYWORD:--%s--", stdout)
	uuids := strings.Fields(stdout)
	existingNodes, err := oc.kube.GetNodes()
	for _, uuid := range uuids {
		for _, node := range existingNodes.Items {
			_, stderr, err := util.RunOVNNbctl("remove", "logical_switch",
				joinSwitch(node.Name), "acls", uuid)
			if err != nil {
				klog.Errorf("remove failed to delete the rule for "+
					"address_set=%s, stderr: %q (%v)", nsInfo.addressSet.GetHashName(), stderr, err)
			}
		}
	}

	// add the port_group
	err = nsInfo.updateNamespacePortGroup(egressFirewall.Namespace)

	//remove the ranges from the struct...
	//remove whitelist
}

func (ef *egressFirewall) addACLToJoinSwitch() {

}

// add port group and rule
//change to addACLToExternalSwitch
func addACLAndRule(joinSwitch, namespace, hashedAddressSetName, ipCIDR, action string, priority int) error {
	match := fmt.Sprintf("match=\"ip4.dst == %s && ip4.src == $%s\"", ipCIDR, hashedAddressSetName)

	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:egressFirewall=%s", namespace))

	if err != nil {
		klog.Errorf("error executing create ACL command, stderr: %q, %+v",
			stderr, err)
	}
	if uuid == "" {
		_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
			fmt.Sprintf("priority=%d", priority),
			fmt.Sprintf("direction=%s", fromLport), match, "action="+action,
			fmt.Sprintf("external-ids:egressFirewall=%s", namespace),
			"--", "add", "logical_switch", joinSwitch,
			"acls", "@acl")
		if err != nil {
			klog.Errorf(" error executing create ACL command, stderr: %q, %+v",
				stderr, err)
			return err
		}
	} else {
		_, stderr, err := util.RunOVNNbctl("add", "logical_switch", joinSwitch, "acls", uuid)
		if err != nil {
			klog.Errorf(" error executing create ACL command, stderr: %q, %+v",
				stderr, err)
			return err

		}
	}

	return nil

}

func joinSwitch(nodeName string) string {
	return fmt.Sprintf("join_%s", nodeName)
}
