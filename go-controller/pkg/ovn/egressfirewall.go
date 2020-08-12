package ovn

import (
	"fmt"
	"net"
	"strings"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	defaultStartPriority           = 2000
	egressFirewallAppliedCorrectly = "EgressFirewall Rules applied"
	egressFirewallAddError         = "EgressFirewall Rules not correctly added"
	egressFirewallUpdateError      = "EgressFirewall Rules did not update correctly"
)

type egressFirewall struct {
	name        string
	namespace   string
	egressRules []*egressFirewallRule
}

type egressFirewallRule struct {
	id     int
	access egressfirewallapi.EgressFirewallRuleType
	ports  []egressfirewallapi.EgressFirewallPort
	to     destination
}

type destination struct {
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
	}

	_, _, err := net.ParseCIDR(rawEgressFirewallRule.To.CIDRSelector)
	if err != nil {
		return nil, err
	}
	efr.to.cidrSelector = rawEgressFirewallRule.To.CIDRSelector

	efr.ports = rawEgressFirewallRule.Ports

	return efr, nil
}

func (oc *Controller) addEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) []error {
	klog.Infof("Adding egress Firewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)
	nsInfo, err := oc.waitForNamespaceLocked(egressFirewall.Namespace)
	if err != nil {
		return []error{fmt.Errorf("failed to wait for namespace %s event (%v)",
			egressFirewall.Namespace, err)}
	}
	defer nsInfo.Unlock()

	if nsInfo.egressFirewallPolicy != nil {
		return []error{fmt.Errorf("error attempting to add egressFirewall %s to namespace %s when it already has an egressFirewall",
			egressFirewall.Name, egressFirewall.Namespace)}
	}

	ef := newEgressFirewall(egressFirewall)
	nsInfo.egressFirewallPolicy = ef
	var errList []error
	for i, egressFirewallRule := range egressFirewall.Spec.Egress {
		//process Rules into egressFirewallRules for egressFirewall struct
		efr, err := newEgressFirewallRule(egressFirewallRule, i)
		if err != nil {
			errList = append(errList, fmt.Errorf("error: cannot create EgressFirewall Rule for destination %s to namespace %s - %v",
				egressFirewallRule.To.CIDRSelector, egressFirewall.Namespace, err))
			continue

		}
		ef.egressRules = append(ef.egressRules, efr)
	}
	if len(errList) > 0 {
		return errList
	}

	existingNodes, err := oc.kube.GetNodes()
	if err != nil {
		return []error{fmt.Errorf("error unable to add egressfirewall %s, cannot list nodes: %s", egressFirewall.Name, err)}
	}
	var joinSwitches []string
	for _, node := range existingNodes.Items {
		joinSwitches = append(joinSwitches, joinSwitch(node.Name))
	}
	err = ef.addACLToJoinSwitch(joinSwitches, nsInfo.addressSet.GetIPv4HashName(), nsInfo.addressSet.GetIPv6HashName())
	if err != nil {
		errList = append(errList, err)
	}
	if len(errList) > 0 {
		return errList
	}

	return nil

}

func (oc *Controller) updateEgressFirewall(oldEgressFirewall, newEgressFirewall *egressfirewallapi.EgressFirewall) []error {
	errList := oc.deleteEgressFirewall(oldEgressFirewall)
	errList = append(errList, oc.addEgressFirewall(newEgressFirewall)...)
	return errList
}

func (oc *Controller) deleteEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) []error {
	klog.Infof("Deleting egress Firewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)

	nsInfo := oc.getNamespaceLocked(egressFirewall.Namespace)
	if nsInfo != nil {
		// clear it so an error does not prevent future egressFirewalls
		nsInfo.egressFirewallPolicy = nil
		nsInfo.Unlock()
	}

	existingNodes, err := oc.kube.GetNodes()
	if err != nil {
		return []error{fmt.Errorf("error deleting egressFirewall for namespace %s, cannot get nodes to delete ACLS %v",
			egressFirewall.Namespace, err)}
	}

	stdout, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:egressFirewall=%s", egressFirewall.Namespace))
	if err != nil {
		return []error{fmt.Errorf("error executing find ACL command, stderr: %q, %+v", stderr, err)}
	}
	var errList []error
	uuids := strings.Fields(stdout)
	for _, uuid := range uuids {
		for _, node := range existingNodes.Items {
			_, stderr, err := util.RunOVNNbctl("remove", "logical_switch",
				joinSwitch(node.Name), "acls", uuid)
			if err != nil {
				errList = append(errList, fmt.Errorf("failed to delete the rules for "+
					"egressFirewall in namespace %s on node %s, stderr: %q (%v)", egressFirewall.Namespace, node.Name, stderr, err))
			}
		}
	}
	return errList
}

func (oc *Controller) updateEgressFirewallWithRetry(egressfirewall *egressfirewallapi.EgressFirewall) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return oc.kube.UpdateEgressFirewall(egressfirewall)
	})
}

func (ef *egressFirewall) addACLToJoinSwitch(joinSwitches []string, hashedAddressSetNameIPv4, hashedAddressSetNameIPv6 string) error {
	for _, rule := range ef.egressRules {
		var action string
		var match string
		if rule.access == egressfirewallapi.EgressFirewallRuleAllow {
			action = "allow"
		} else {
			action = "drop"
		}
		ip, _, err := net.ParseCIDR(rule.to.cidrSelector)
		if err != nil {
			// should not happen because this value is already validated
			return fmt.Errorf("cannot add ACL %s is not a valid CIDR", rule.to.cidrSelector)
		}
		if utilnet.IsIPv6(ip) {
			match, err = generateMatch(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, []matchTarget{matchTarget{matchKindV6CIDR, rule.to.cidrSelector}}, rule.ports)
		} else {
			match, err = generateMatch(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, []matchTarget{matchTarget{matchKindV4CIDR, rule.to.cidrSelector}}, rule.ports)
		}
		match := generateMatch(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, matchTargets, rule.ports)
		for _, joinSwitch := range joinSwitches {
			err = createACLRule(defaultStartPriority-rule.id, match, action, ef.namespace, joinSwitch)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func createACLRule(priority int, match, action, namespace, joinSwitch string) error {
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:egressFirewall=%s", namespace))

	if err != nil {
		return fmt.Errorf("error executing find ACL command, stderr: %q, %+v", stderr, err)
	}
	if uuid == "" {
		_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
			fmt.Sprintf("priority=%d", priority),
			fmt.Sprintf("direction=%s", fromLport),
			match, "action="+action,
			fmt.Sprintf("external-ids:egressFirewall=%s", namespace),
			"--", "add", "logical_switch", joinSwitch,
			"acls", "@acl")
		if err != nil {
			return fmt.Errorf("error adding ACL to joinsSwitch %s failed, stderr: %q, %+v", joinSwitch, stderr, err)
		}
	} else {
		_, stderr, err := util.RunOVNNbctl("add", "logical_switch", joinSwitch, "acls", uuid)
		if err != nil {
			return fmt.Errorf("error adding ACL to joinsSwitch %s failed, stderr: %q, %+v", joinSwitch, stderr, err)

		}
	}
	return nil
}

type matchTarget struct {
	kind  matchKind
	value string
}

type matchKind int

const (
	matchKindV4CIDR matchKind = iota
	matchKindV6CIDR
	matchKindV4AddressSet
	matchKindV6AddressSet
)

func (m *matchTarget) toExpr() string {
	switch m.kind {
	case matchKindV4CIDR:
		return fmt.Sprintf("ip4.dst == %s || ", m.value)
	case matchKindV6CIDR:
		return fmt.Sprintf("ip6.dst == %s || ", m.value)
	case matchKindV4AddressSet:
		if m.value != "" {
			return fmt.Sprintf("ip4.dst == $%s || ", m.value)
		}
		return ""
	case matchKindV6AddressSet:
		if m.value != "" {
			return fmt.Sprintf("ip6.dst == $%s || ", m.value)
		}
		return ""
	}
	panic("invalid matchKind")
}

// generateMatch generates the "match" section of ACL generation for egressFirewallRules.
// It is referentially transparent as all the elements have been validated before this function is called
// sample output:
// match=\"(ip4.src == $ipv4AddressSetHash || ip6.src == $ipv6AddressSetHash) && (ip6.dst == 2001::/64)\"
func generateMatch(ipv4Source, ipv6Source string, destinations []matchTarget, ports []egressfirewallapi.EgressFirewallPort) string {
	var src string
	var dst string
	if ipv4Source == "" {
		src = "ip4.src != 0.0.0.0/0"
	} else {
		src = fmt.Sprintf("ip4.src == $%s", ipv4Source)
	}
	if ipv6Source == "" {
		src = fmt.Sprintf("%s || ip6.src != ::/0", src)
	} else {
		src = fmt.Sprintf("%s || ip6.src == $%s", src, ipv6Source)
	}

	for _, entry := range destinations {
		dst = fmt.Sprintf("%s%s", dst, entry.toExpr())
	}

	// remove the last 4 characters from dst because I always append " || " and the last entry does not need it
	match := fmt.Sprintf("match=\"(%s) && (%s)\"", src, dst[:len(dst)-4])

	if len(ports) > 0 {
		// remove the last character of match because that is the ending " character
		match = fmt.Sprintf("%s && ( %s )\"", match[:len(match)-1], egressGetL4Match(ports))
	}

	return match
}

// egressGetL4Match generates the rules for when ports are specified in an egressFirewall Rule
// since the ports can be specified in any order in an egressFirewallRule the best way to build up
// a single rule is to build up each protocol as you walk through the list and place the appropriate logic
// between the elements.
func egressGetL4Match(ports []egressfirewallapi.EgressFirewallPort) string {
	var udpString string
	var tcpString string
	var sctpString string
	for _, port := range ports {
		if kapi.Protocol(port.Protocol) == kapi.ProtocolUDP && udpString != "udp" {
			if port.Port == 0 {
				udpString = "udp"
			} else {
				udpString = fmt.Sprintf("%s udp.dst == %d ||", udpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolTCP && tcpString != "tcp" {
			if port.Port == 0 {
				tcpString = "tcp"
			} else {
				tcpString = fmt.Sprintf("%s tcp.dst == %d ||", tcpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolSCTP && sctpString != "sctp" {
			if port.Port == 0 {
				sctpString = "sctp"
			} else {
				sctpString = fmt.Sprintf("%s sctp.dst == %d ||", sctpString, port.Port)
			}
		}
	}
	// build the l4 match
	var l4Match string
	type tuple struct {
		protocolName     string
		protocolFormated string
	}
	list := []tuple{
		{
			protocolName:     "udp",
			protocolFormated: udpString,
		},
		{
			protocolName:     "tcp",
			protocolFormated: tcpString,
		},
		{
			protocolName:     "sctp",
			protocolFormated: sctpString,
		},
	}
	for _, entry := range list {
		if entry.protocolName == entry.protocolFormated {
			if l4Match == "" {
				l4Match = fmt.Sprintf("(%s)", entry.protocolName)
			} else {
				l4Match = fmt.Sprintf("%s || (%s)", l4Match, entry.protocolName)
			}
		} else {
			if l4Match == "" && entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("(%s && (%s))", entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			} else if entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("%s || (%s && (%s))", l4Match, entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			}
		}
	}
	return l4Match
}

func joinSwitch(nodeName string) string {
	return fmt.Sprintf("join_%s", nodeName)
}
