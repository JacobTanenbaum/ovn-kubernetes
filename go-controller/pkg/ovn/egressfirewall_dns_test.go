package ovn

import (
	//"context"
	//"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog"
)

var _ = Describe("EgressFirewall_dns", func() {
	var (
		app   *cli.App
		fExec *ovntest.FakeExec

	//fakeOVN *FakeOVN
	//fExec *ovntest.FakeExec
	//asFactory AddressSetFactory
	)
	BeforeEach(func() {
		klog.Errorf("KEYWORD THIS IS THE VERY START?")
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		err := util.SetExec(fExec)
		Expect(err).NotTo(HaveOccurred())
		//fakeOVN = NewFakeOVN(fExec)
	})

	AfterEach(func() {
	})

	It("does something I am stubing this right now", func() {
		app.Action = func(ctx *cli.Context) error {
			klog.Errorf("KEYWORD THIS IS IN MY TEST")
			type testcase struct {
				joinSwitches     []string
				namespace        string
				dnsName          string
				action           string
				hashedAddressSet string
				portMatch        string
				priority         int
			}
			testcases := []testcase{
				{
					joinSwitches:     []string{"join_node1", "join_node2"},
					namespace:        "testing",
					dnsName:          "www.testing.com",
					action:           "allow",
					hashedAddressSet: "addressSet",
					portMatch:        "",
					priority:         200,
				},
			}
			klog.Errorf("KEYWORD HMMMM")
			for _, test := range testcases {
				config.IPv4Mode = true
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=" + hashedAddressSet(getIPv4ASName(test.dnsName)),
					"ovn-nbctl --timeout=15 create address_set name=" + hashedAddressSet(getIPv4ASName(test.dnsName)) + " external-ids:name=" + test.dnsName + "_v4",
				})
				//asFactory = NewOvnAddressSetFactory()
				stopChan := make(<-chan struct{})
				klog.Errorf("KEYWORD ******    ")
				//fakeOVN.controller.addressSetFactory = NewOvnAddressSetFactory()
				//fakeOVN.start(nil)
				egressDNS, err := NewEgressDNS(NewOvnAddressSetFactory(), stopChan)
				klog.Errorf("KEYWORD WHAAAAA")
				if err != nil {
					klog.Errorf("KEYWORD: NOOOOOOOOO!")
				}
				klog.Errorf("KEYWORD\n")
				egressDNS.Add(test.namespace, test.dnsName)
				klog.Errorf("KEYWORD: %s\n", egressDNS.dnsEntries[test.namespace])
				Expect(egressDNS.dnsEntries[test.namespace]).To(Equal(nil))
				egressDNS.Delete(test.namespace)

			}
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())

	})

})
