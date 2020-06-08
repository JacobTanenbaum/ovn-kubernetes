package ovn

import (
	"fmt"
	"strings"
	"sync"

	//"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	"k8s.io/klog"
)

/*
*****NOTES*****
addPodToNamespace already adds the address of the pod to the address set


Since the rules are processed from top to bottom that means that some can overlap and while the whitelisting
of all internal ip addresses needs to be highest all subsequent rules need to be of a different priority level becuase
they can overlap and the first one that is defined needs to be followed


Since I have to enforce an order if an egressFirewall Object is modified I need to delete and recreate it.
*/

const (
	//	toLport = "to-lport"
	//fromLport = "from-lport" -- use this one
	//default priority to whitelist internal traffic
	//defaultWhitelistPriority = 2000
	defaultStartPriority = 2000
)

//could use the namespacePolicy?...KEYWORD

type egressFirewall struct {
	sync.Mutex  //not sure if needed
	name        string
	namespace   string
	egressRules []*egressFirewallRule
}

type egressFirewallRule struct {
	id     int
	access egressfirewallapi.EgressFirewallRuleType //ALLOW or DENY
	ports  []*port                                  //the ports that this rule applies to
	to     destination                              //either a DNS name or cidr selector
}

// KEYWORD: can use port policy struct from policy.go?
type port struct {
	protocol *v1.Protocol //UDP, TCP, SCTP
	portNum  *int32
}

type destination struct { //could make it all a CIDR selector and resolve DNS namespace here KEYWORD
	dnsName      string
	cidrSelector string
}

func newEgressFirewall(egressFirewallPolicy *egressfirewallapi.EgressFirewall) *egressFirewall {
	ef := &egressFirewall{
		name:        egressFirewallPolicy.Name,
		namespace:   egressFirewallPolicy.Namespace,
		egressRules: make([]*egressFirewallRule, 0),
	}
	return ef
}

func newEgressFirewallRule(rawEgressFirewallRule egressfirewallapi.EgressFirewallRule, id int) (*egressFirewallRule, error) {
	efr := &egressFirewallRule{
		id:     id,
		access: rawEgressFirewallRule.Type,
		ports:  make([]*port, 0),
		//destinations: make([]*destination, 0),
	}

	if (rawEgressFirewallRule.To.DNSName == "" || rawEgressFirewallRule.To.CIDRSelector != "") &&
		(rawEgressFirewallRule.To.DNSName != "" || rawEgressFirewallRule.To.CIDRSelector == "") {
		return nil, fmt.Errorf("EgressFirewallRule must have either a CIDRSelector or DNSName set")
	}

	efr.to.dnsName = rawEgressFirewallRule.To.DNSName
	efr.to.cidrSelector = rawEgressFirewallRule.To.CIDRSelector

	for _, rawPort := range rawEgressFirewallRule.Ports {
		port := port{}
		if rawPort.Protocol != nil {
			port.protocol = rawPort.Protocol
		}
		if rawPort.PortNum != nil {
			port.portNum = rawPort.PortNum
		}
	}

	return efr, nil
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
		efr, err := newEgressFirewallRule(egressFirewallRule, i)
		if err != nil {
			klog.Errorf("Cannot create EgressFirewall %s to namespace %s - %v",
				egressFirewall.Name, egressFirewall.Namespace, err)

		}
		ef.egressRules = append(ef.egressRules, efr)
	}

	// TODO make a function that takes an egressFirewall struct and adds all the ACLs in it...
	existingNodes, err := oc.kube.GetNodes()
	if err != nil {
		klog.Errorf("KEYWORD: UNABLE TO GET NODES")
	}
	for _, node := range existingNodes.Items {

		joinSwitch := joinSwitch(node.Name)
		ef.addACLToJoinSwitch(joinSwitch, nsInfo.addressSet.GetHashName())
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
}

func (ef *egressFirewall) addACLToJoinSwitch(joinSwitch, hashedAddressSetName string) error {
	// l3Match is "Easy" it is the ip4 address from the CIDR or the dnsName as ip4.dst
	//l4 match is  (tcp && (tcp.dst == x || tcp.dst == y)) || (udp && (udp.dst == x || udp.dst == y)) || (sctp && (sctp.dst == x ||
	//match is l3Match && l4Match
	for _, rule := range ef.egressRules {
		var match string
		var action string
		if rule.access == egressfirewallapi.EgressFirewallRuleAllow {
			action = "allow"
		} else {
			action = "drop"
		}

		//TODO
		// - determine if using cidrSelector or DNSname
		//   - dnsResolver stuff
		// - add the port match generation code

		if len(rule.ports) == 0 {
			match = fmt.Sprintf("match=\"ip4.dst == %s && ip4.src == $%s\"", rule.to.cidrSelector, hashedAddressSetName)
		}
		uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "ACL", match, "action="+action,
			fmt.Sprintf("external-ids:egressFirewall=%s", ef.namespace))

		if err != nil {
			klog.Errorf("error executing find ACL command, stderr: %q, %+v",
				stderr, err)
		}
		if uuid == "" {
			_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
				fmt.Sprintf("priority=%d", defaultStartPriority-rule.id),
				fmt.Sprintf("direction=%s", fromLport), match, "action="+action,
				fmt.Sprintf("external-ids:egressFirewall=%s", ef.namespace),
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

	}
	return nil
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

func egressGetL4Match(ports []*port) (string, error) {
	var udpString string
	var tcpString string
	var sctpString string
	for _, port := range ports {
		if port.protocol != nil && *port.protocol == "UDP" && udpString != "udp" {
			if port.portNum == nil {
				udpString = "udp"
			} else {
				udpString = fmt.Sprintf("%s udp.dst == %d ||", udpString, *port.portNum)
			}
		} else if port.protocol != nil && *port.protocol == "TCP" && tcpString != "tcp" {
			if port.portNum == nil {
				tcpString = "tcp"
			} else {
				tcpString = fmt.Sprintf("%s tcp.dst == %d ||", tcpString, *port.portNum)
			}
		} else if port.protocol != nil && *port.protocol == "SCTP" && tcpString != "sctp" {
			if port.portNum == nil {
				sctpString = "sctp"
			} else {
				sctpString = fmt.Sprintf("%s sctp.dst == %d ||", sctpString, *port.portNum)
			}
		}
	}
	// build the l4 match
	var l4Match string
	for protocol, string := range map[string]string{"udp": udpString, "tcp": tcpString, "sctp": sctpString} {
		if string == protocol {
			if l4Match == "" {
				l4Match = fmt.Sprintf("(%s)", protocol)
			} else {
				l4Match = fmt.Sprintf("%s || (%s)", l4Match, protocol)
			}
		} else {
			if l4Match == "" && string != "" {
				l4Match = fmt.Sprintf("(%s && (%s))", protocol, udpString[:len(udpString)-2])
			} else if string != "" {
				l4Match = fmt.Sprintf("%s || (%s && (%s))", l4Match, protocol, string[:len(string)-2])
			}
		}
	}
	return l4Match, nil
}

func joinSwitch(nodeName string) string {
	return fmt.Sprintf("join_%s", nodeName)
}
