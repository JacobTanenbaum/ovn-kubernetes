package ovn

import (
	"context"
	"fmt"
	"net"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	dnsobjectapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/dnsobject/v1"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	t "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
	}

}

func newEgressFirewallObject(name, namespace string, egressRules []egressfirewallapi.EgressFirewallRule) *egressfirewallapi.EgressFirewall {

	return &egressfirewallapi.EgressFirewall{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressfirewallapi.EgressFirewallSpec{
			Egress: egressRules,
		},
	}
}

//new DNSObject creates a dnsObject for testing the dnsNameMap is map[dnsName]ipaddresses
func newDNSObject(name string, dnsObjectEntries map[string]dnsobjectapi.DNSObjectEntry) *dnsobjectapi.DNSObject {

	return &dnsobjectapi.DNSObject{
		ObjectMeta: newObjectMeta(name, ""),
		Spec: dnsobjectapi.DNSObjectSpec{
			DNSObjectEntries: dnsObjectEntries,
		},
	}
}

var _ = ginkgo.Describe("OVN EgressFirewall Operations for local gateway mode", func() {
	var (
		app     *cli.App
		fakeOVN *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each 99999e
		config.PrepareTestConfig()
		config.Gateway.Mode = config.GatewayModeLocal

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOVN = NewFakeOVN(fExec)

	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.Context("on startup", func() {
		ginkgo.It("reconciles an existing egressFirewall with IPv4 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("reconciles an existing egressFirewall with IPv6 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					}, &v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				config.IPv6Mode = true
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("reconciles an existing DNSObject and egressFirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == $a13161312698469205037 || ip6.dst == $a13161310499445948615) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy"})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				dnsObject := newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						Namespaces:  []string{namespace1.Name},
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&dnsobjectapi.DNSObjectList{
						Items: []dnsobjectapi.DNSObject{
							*dnsObject,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					}, &v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				config.IPv6Mode = true
				//TODO: change the fake addressSetFactory code to use the mocks library
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()
				fakeOVN.asf.EventuallyExpectEmptyAddressSet("www.google.com")
				fakeOVN.controller.WatchDNSObject()
				fakeOVN.asf.ExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1"})
				//verify that the egressfirewallDNSInfo struct is correct
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					node1Name: struct{}{},
				}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					egressFirewall.Namespace: struct{}{},
				}))

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})

	})
	ginkgo.Context("during execution", func() {
		ginkgo.It("correctly creates an egressfirewall denying traffic udp traffic on port 100", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly creates an egressfirewall denying traffic udp traffic on port 100 and DNS Allow", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				dnsObject := newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						Namespaces:  []string{namespace1.Name},
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&dnsobjectapi.DNSObjectList{
						Items: []dnsobjectapi.DNSObject{
							*dnsObject,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()
				fakeOVN.asf.EventuallyExpectEmptyAddressSet("www.google.com")
				fakeOVN.controller.WatchDNSObject()
				fakeOVN.asf.ExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1"})
				//verify that the egressfirewallDNSInfo struct is correct
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					node1Name: struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).To(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
				}))

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly deletes an egressfirewall", func() {
			//fakeUUID2 = "12345"
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "TCP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.5/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly deletes an egressfirewall with DNS", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
					fakeUUID2 string = "12345"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					// egressfirewall adding for namespace1
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && " +
						"ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && " +
						"ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					// egressfirewall adding for namespace2
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && " +
						"ip4.src == $a4615334824109672969 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID2),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace2",
					Output: fmt.Sprintf("%s", fakeUUID2),
				})
				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				egressFirewall2 := newEgressFirewallObject("default", namespace2.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				dnsObject1 := newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				dnsObject2 := newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "2.2.2.2"},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall1,
							*egressFirewall2,
						},
					},
					&dnsobjectapi.DNSObjectList{
						Items: []dnsobjectapi.DNSObject{
							*dnsObject1,
							*dnsObject2,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Get(context.TODO(), egressFirewall1.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()
				fakeOVN.asf.EventuallyExpectEmptyAddressSet("www.google.com")
				fakeOVN.controller.WatchDNSObject()
				fakeOVN.asf.ExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					node1Name: struct{}{},
					"node2":   struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).To(gomega.Equal(map[string]struct{}{
					"node2": struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).To(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))

				//case 1: a node gets deleted but nothing with the egressfirewall itself changes
				err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Delete(context.TODO(), dnsObject2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1"})
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					node1Name: struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).To(gomega.BeNil())
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).To(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))

				//case 2: An egressFirewall gets deleted that shares DNS information with another egressFirewall
				err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(namespace1.Name).Delete(context.TODO(), egressFirewall1.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					node1Name: struct{}{},
				}))

				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace2.Name: struct{}{},
				}))

				//case 3. the last egressfirewall with a DNS name gets deleted, deleting the address set and the dns struct, Here I will use the egressFirewall being deleted, there is also the case
				// that an egressFirewall is updated removing the DNS name which will be handled with the update case. For purposes of testing after the egressFirewall is deleted I will manually delete
				// the dnsObject which the node would normally do.
				err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(namespace2.Name).Delete(context.TODO(), egressFirewall2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				name4, _ := addressset.MakeAddressSetName("www.google.com")
				fakeOVN.asf.EventuallyExpectNoAddressSet(name4)
				//mimic deleteing the DNSObject this would normally be done by the node doing it here to ensure no panic
				err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Delete(context.TODO(), dnsObject1.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly updates an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=10000 match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", fakeUUID),
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("correctly updates an egressfirewall with DNS", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
					fakeUUID2 string = "12345"
					//a common UUID I will be using for the block commands, just to make life a little easier
					blockUUID string = "block"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					// egressfirewall adding for namespace1
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && " +
						"ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && " +
						"ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					// egressfirewall adding for namespace2
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && " +
						"ip4.src == $a4615334824109672969 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",

					//first update of egressfirewall1 for case #1
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=10000 match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9997 match=\"(ip4.dst == $a6708137140038977205) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", blockUUID),

					//first update of egressfirewall2 for case #2
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=10000 match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2-blockAll -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a4615334824109672969 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9997 match=\"(ip4.dst == $a6708137140038977205) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", blockUUID),

					//second update of egressfirewall2 for case #3
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=10000 match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2-blockAll -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace2",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a4615334824109672969 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a4615334824109672969 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace2 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", blockUUID),

					//second update of egressfirewall1 for case #4
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=10000 match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9999 match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 --id=@logical_router_policy create logical_router_policy priority=9998 match=\"(ip4.dst == $a13161312698469205037) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=allow external-ids:egressFirewall=namespace1 -- add logical_router ovn_cluster_router policies @logical_router_policy",
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", blockUUID),

					//removing egressfirewall1
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID),
					// removing egressfirewall2
					"ovn-nbctl --timeout=15 lr-policy-del ovn_cluster_router " + fmt.Sprintf("%s", fakeUUID2),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall1- blockALl
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", blockUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall1- blockALl
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", blockUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall2-blockALl
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace2-blockAll",
					Output: fmt.Sprintf("%s", blockUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall2-blockALl
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace2-blockAll",
					Output: fmt.Sprintf("%s", blockUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall1
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall1
					Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace1",

					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					//removing egressfirewall2
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_policy external-ids:egressFirewall=namespace2",
					Output: fmt.Sprintf("%s", fakeUUID2),
				})
				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				egressFirewall2 := newEgressFirewallObject("default", namespace2.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				dnsObject1 := newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				dnsObject2 := newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "2.2.2.2"},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall1,
							*egressFirewall2,
						},
					},
					&dnsobjectapi.DNSObjectList{
						Items: []dnsobjectapi.DNSObject{
							*dnsObject1,
							*dnsObject2,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				//The cases that need to be delt with
				// 1. An egressFirewall is updated adding new unique dnsName
				// 2. An egressFirewall is updated adding new shared dnsName
				// 3. An egressFirewall is updated removing a shared dnsName
				// 4. An egressFirewall is updated removing a unique dnsName
				// 5. A dnsObject is updated adding a new unique ip address for a dnsName
				// 6. A dnsObject is updated adding a new shared ip address for a dnsName
				// 7. A dnsObject is updated removing a unique ip address for a dnsName
				// 8. A dnsObject is updated removing a shared ip address for a dnsName

				//case 1 An egressFirewall is updated adding a new unique dnsName
				egressFirewall1 = newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.github.com",
						},
					},
				})
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()
				fakeOVN.controller.WatchDNSObject()
				// adding the dnsName www.github.com to egresssfirewall1
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// when the new DNS names get added the master creates the address set and the Namespace section of the locally stored data in egressfirewallDNSInfo

				fakeOVN.asf.EventuallyExpectEmptyAddressSet("www.github.com")
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.github.com"].Namespaces).To(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
				}))
				//in a real cluster the node would update the dns object I will simulate that by manually updating
				// both my DNS objects will update
				dnsObject1 = newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1"},
					},
					"www.github.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"9.9.9.9", "8.8.8.8"},
					},
				})
				dnsObject2 = newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "2.2.2.2"},
					},
					"www.github.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"9.9.9.9", "4.4.4.4"},
					},
				})

				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// the dnsObjectWatcher, adds IP addresses to the appropriate addressSet
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.github.com", []string{"9.9.9.9", "8.8.8.8", "4.4.4.4"})
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})
				fmt.Printf("KEYWORD: WHAT IS HAPPENING HERE\n")
				// case 2: an egressfirewall gets updated adding a shared DNS name
				//adding the dnsName www.github.com to egressfirewall2
				egressFirewall2 = newEgressFirewallObject("default", namespace2.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.github.com",
						},
					},
				})
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall2.Namespace).Update(context.TODO(), egressFirewall2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// the only change that would happen in this case is the additional Namespace should be added to the egressfirewallDNSInfo
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.github.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.github.com", []string{"9.9.9.9", "8.8.8.8", "4.4.4.4"})
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})

				//case #3 removing shared DNSname
				egressFirewall2 = newEgressFirewallObject("default", namespace2.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall2.Namespace).Update(context.TODO(), egressFirewall2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.github.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
				}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.github.com", []string{"9.9.9.9", "8.8.8.8", "4.4.4.4"})
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})

				//case #4 removing a unique DNSName
				egressFirewall1 = newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							DNSName: "www.google.com",
						},
					},
				})
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				//removing the last namspace that has a referance to github.com the AddressSet will be deleted as well as the entry in the egressfirewallDNSInfo
				fakeOVN.asf.EventuallyExpectNoAddressSet("www.github.com")

				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})

				//becuase the egressfirewall was updated the nodes would update the dnsObjects so I will simulate that here
				dnsObject1 = newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				dnsObject2 = newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "2.2.2.2"},
					},
				})

				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				//the updates on the node should not cause any updates on the master
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2"})

				// Cases 5,6,7,8 deal with dnsObject updates coming from the nodes
				// case #5 A dnsObject is updated adding a new unique ip address for a dnsName
				dnsObject1 = newDNSObject(node1Name, map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "3.3.3.3"},
					},
				})
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].Namespaces).Should(gomega.Equal(map[string]struct{}{
					namespace1.Name: struct{}{},
					namespace2.Name: struct{}{},
				}))
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
				//check all the ipNodes sections to make sure all the entries are correct
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).To(gomega.Equal(map[string]struct{}{
					dnsObject2.Name: struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["3.3.3.3"]).To(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
				}))

				// case #6 A dnsObject is updated adding a new shared ip address for a dnsName
				dnsObject2 = newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
					},
				})
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).To(gomega.Equal(map[string]struct{}{
					dnsObject2.Name: struct{}{},
				}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["3.3.3.3"]).Should(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))

				// case #7 A dnsObject is updated removing a unique ip address for a dnsName
				dnsObject2 = newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1", "3.3.3.3"},
					},
				})
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).Should(gomega.Equal(map[string]struct{}{}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["3.3.3.3"]).Should(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))

				// case #8 A dnsObject is updated removing a shared ip address for a dnsName
				dnsObject2 = newDNSObject("node2", map[string]dnsobjectapi.DNSObjectEntry{
					"www.google.com": dnsobjectapi.DNSObjectEntry{
						IPAddresses: []string{"1.1.1.1"},
					},
				})
				_, err = fakeOVN.fakeClient.DNSObjectClient.K8sV1().DNSObjects().Update(context.TODO(), dnsObject2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["1.1.1.1"]).To(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
					dnsObject2.Name: struct{}{},
				}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["2.2.2.2"]).Should(gomega.Equal(map[string]struct{}{}))
				gomega.Eventually(fakeOVN.controller.egressfirewallDNSInfo["www.google.com"].ipNodes["3.3.3.3"]).Should(gomega.Equal(map[string]struct{}{
					dnsObject1.Name: struct{}{},
				}))
				fakeOVN.asf.EventuallyExpectAddressSetWithIPs("www.google.com", []string{"1.1.1.1", "3.3.3.3"})

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

})

var _ = ginkgo.Describe("OVN EgressFirewall Operations for shared gateway mode", func() {
	var (
		app     *cli.App
		fakeOVN *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each 99999e
		config.PrepareTestConfig()
		config.Gateway.Mode = config.GatewayModeShared

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOVN = NewFakeOVN(fExec)

	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.Context("on startup", func() {
		ginkgo.It("reconciles an existing egressFirewall with IPv4 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("reconciles an existing egressFirewall with IPv6 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					}, &v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				config.IPv6Mode = true
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
	})
	ginkgo.Context("during execution", func() {
		ginkgo.It("correctly creates an egressfirewall denying traffic udp traffic on port 100", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly deletes an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "TCP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.5/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly updates an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1-blockAll",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=10000 direction=from-lport match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=from-lport match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})

	})

})

var _ = ginkgo.Describe("OVN test basic functions", func() {

	ginkgo.It("computes correct L4Match", func() {
		type testcase struct {
			ports         []egressfirewallapi.EgressFirewallPort
			expectedMatch string
		}
		testcases := []testcase{
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
				},
				expectedMatch: "((tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "UDP",
					},
				},
				expectedMatch: "((udp) || (tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "SCTP",
						Port:     13,
					},
					{
						Protocol: "TCP",
						Port:     102,
					},
					{
						Protocol: "UDP",
						Port:     400,
					},
				},
				expectedMatch: "((udp && ( udp.dst == 400 )) || (tcp && ( tcp.dst == 100 || tcp.dst == 102 )) || (sctp && ( sctp.dst == 13 )))",
			},
		}
		for _, test := range testcases {
			l4Match := egressGetL4Match(test.ports)
			gomega.Expect(test.expectedMatch).To(gomega.Equal(l4Match))
		}
	})
	ginkgo.It("computes correct match function", func() {
		type testcase struct {
			internalCIDR string
			ipv4source   string
			ipv6source   string
			destinations []matchTarget
			ports        []egressfirewallapi.EgressFirewallPort
			output       string
		}
		testcases := []testcase{
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "",
				destinations: []matchTarget{{matchKindV4CIDR, "1.2.3.4/32"}},
				ports:        nil,
				output:       `match="(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV4CIDR, "1.2.3.4/32"}},
				ports:        nil,
				output:       `match="(ip4.dst == 1.2.3.4/32) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV4AddressSet, "destv4"}, {matchKindV6AddressSet, "destv6"}},
				ports:        nil,
				output:       `match="(ip4.dst == $destv4 || ip6.dst == $destv6) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "",
				destinations: []matchTarget{{matchKindV4AddressSet, "destv4"}, {matchKindV6AddressSet, ""}},
				ports:        nil,
				output:       `match="(ip4.dst == $destv4) && ip4.src == $testv4 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV6CIDR, "2001::/64"}},
				ports:        nil,
				output:       `match="(ip6.dst == 2001::/64) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "2002:0:0:1234::/64",
				ipv4source:   "",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV6AddressSet, "destv6"}},
				ports:        nil,
				output:       `match="(ip6.dst == $destv6) && ip6.src == $testv6 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
		}

		for _, tc := range testcases {
			_, cidr, _ := net.ParseCIDR(tc.internalCIDR)
			config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{CIDR: cidr}}
			config.Gateway.Mode = config.GatewayModeShared
			matchExpression := generateMatch(tc.ipv4source, tc.ipv6source, tc.destinations, tc.ports)
			gomega.Expect(tc.output).To(gomega.Equal(matchExpression))
		}
	})
	ginkgo.It("correctly parses egressFirewallRules", func() {
		type testcase struct {
			egressFirewallRule egressfirewallapi.EgressFirewallRule
			id                 int
			err                bool
			errOutput          string
			output             egressFirewallRule
		}
		testcases := []testcase{
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "1.2.3.4/32"},
				},
			},
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3./32"},
				},
				id:        1,
				err:       true,
				errOutput: "invalid CIDR address: 1.2.3./32",
				output:    egressFirewallRule{},
			},
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64"},
				},
				id:  2,
				err: false,
				output: egressFirewallRule{
					id:     2,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002::1234:abcd:ffff:c0a8:101/64"},
				},
			},
		}
		for _, tc := range testcases {
			output, err := newEgressFirewallRule(tc.egressFirewallRule, tc.id)
			if tc.err == true {
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(tc.errOutput).To(gomega.Equal(err.Error()))
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(tc.output).To(gomega.Equal(*output))
			}
		}
	})
})

//helper functions to help test egressfirewallDNS

// Create an EgressDNS object without the Sync function
// To make it easier to mock EgressFirewall functionality create an egressFirewall
// without the go routine of the sync function

//GetDNSEntryForTest Gets a dnsEntry from a EgressDNS object for testing
/*
func (e *EgressDNS) GetDNSEntryForTest(dnsName string) (map[string]struct{}, []net.IP, addressset.AddressSet, error) {
	if e.dnsEntries[dnsName] == nil {
		return nil, nil, nil, fmt.Errorf("there is no dnsEntry for dnsName: %s", dnsName)
	}
	return e.dnsEntries[dnsName].namespaces, e.dnsEntries[dnsName].dnsResolves, e.dnsEntries[dnsName].dnsAddressSet, nil
}
*/
