package ovn

import (
	//"context"
	//"fmt"
	//. "github.com/onsi/ginkgo"
	//. "github.com/onsi/gomega"
	"testing"
	"time"

	//	"github.com/urfave/cli/v2"

	"github.com/miekg/dns"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	//ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	util_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	//	"github.com/stretchr/testify/assert"
	mock_k8s_io_utils_exec "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/utils/exec"
	"k8s.io/klog"
)

/*
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

				mockDNSOps := new(util_mocks.DNSOps)
				util.SetDNSLibOpsMockInst(mockDNSOps)

				config.IPv4Mode = true
				var clientConfig = dns.ClientConfig{}
				mockDNSOps.On("ClientConfigFromFile", "/etc/resolv.conf").Return(&clientConfig).Once()
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
*/

//Create an EgressDNS object without the Sync function
func NewEgressDNSForTesting(addressSetFactory AddressSetFactory, controllerStop <-chan struct{}) *EgressDNS {
	dnsInfo, _ := util.NewDNS("/etc/resolv.config")

	return &EgressDNS{
		dns:               dnsInfo,
		dnsEntries:        make(map[string]*dnsEntry),
		addressSetFactory: addressSetFactory,

		added:          make(chan bool),
		stopChan:       make(chan struct{}),
		controllerStop: controllerStop,
	}
}

func TestStuff(t *testing.T) {
	//app := cli.NewApp()
	//app.Name = "test"
	//app.Flags = config.Flags

	//fExec := ovntest.NewLooseCompareFakeExec()
	//err := util.SetExec(fExec)
	tests := []struct {
		name      string
		dnsName   string
		ipAddress string
		dnsConfig dns.ClientConfig
	}{
		{
			dnsName:   "www.testing.com",
			ipAddress: "9.9.9.9",
			dnsConfig: dns.ClientConfig{
				Servers: []string{"1.1.1.1"},
				Port:    "1234",
			},
		},
		{
			dnsName:   "www.testing.com",
			ipAddress: "9.9.9.9",
			dnsConfig: dns.ClientConfig{
				Servers: []string{"1.1.1.1"},
				Port:    "1234",
			},
		},
	}

	//assert.Equal(t, err, nil)
	//creating the address_set
	for _, test := range tests {
		//	fExec.AddFakeCmdsNoOutputNoError([]string{
		//		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=" + hashedAddressSet(getIPv4ASName(test.dnsName)),
		//		"ovn-nbctl --timeout=15 create address_set name=" + hashedAddressSet(getIPv4ASName(test.dnsName)) + " external-ids:name=" + test.dnsName + "_v4",
		//	})

		// add IP to addressSet
		//	fExec.AddFakeCmdsNoOutputNoError([]string{
		//		"ovn-nbctl --timeout=15 add address_set  addresses \"" + test.ipAddress + "\"",
		//	})
		//mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
		//mockExecRunner := new(util_mocks.ExecRunner)
		//mockCmd := new(mock_k8s_io_utils_exec.Cmd)
		// below is defined in ovs.go
		//runCmdExecRunner = mockExecRunner
		// note runner is defined in ovs.go file
		//runner = &execHelper{exec: mockKexecIface}
		//	app.Action = func(ctx *cli.Context) error {
		mockExec := new(mock_k8s_io_utils_exec.Interface)
		util.SetExec(mockExec)
		mockExec.On("LookPath", "ip").Return("fake", nil).Times(20)
		mockDNSOps := new(util_mocks.DNSOps)
		// this happen once per egressDNS.Add()
		mockDNSOps.On("ClientConfigFromFile", "/etc/resolv.config").Return(&test.dnsConfig, nil)
		// these happen twice per egressDNS.Add()
		mockDNSOps.On("Fqdn", test.dnsName).Return(test.dnsName).Twice() //the answer is the same from ipv4 and ipv6
		msg := new(dns.Msg)
		msg1 := new(dns.Msg)
		mockDNSOps.On("SetQuestion", msg, test.dnsName, dns.TypeA).Return(msg).Once()
		mockDNSOps.On("SetQuestion", msg, test.dnsName, dns.TypeAAAA).Return(msg).Once()
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		//returned message for IPv4
		returnedMessage := new(dns.Msg)
		rr, _ := dns.NewRR("www.testing.com.        300     IN      A       " + test.ipAddress)
		returnedMessage.Answer = []dns.RR{rr}

		mockDNSOps.On("Exchange", c, msg, test.dnsConfig.Servers[0]+":"+test.dnsConfig.Port).Return(returnedMessage, 5*time.Second, nil).Once()
		mockDNSOps.On("Exchange", c, msg1, test.dnsConfig.Servers[0]+":"+test.dnsConfig.Port).Return(nil, 5*time.Second, nil).Once()
		util.SetDNSLibOpsMockInst(mockDNSOps)
		config.IPv4Mode = true
		stopChan := make(<-chan struct{})

		egressDNS := NewEgressDNSForTesting(NewOvnAddressSetFactory(), stopChan)
		egressDNS.Add("test", "www.testing.com")
		klog.Errorf("KEYWORD egressDNS: %v", egressDNS)
		klog.Errorf("KEYWORD egressDNS.GetIPS = %s", egressDNS.GetIPs("www.testing.com"))
		klog.Errorf("KEYWORD egressDNS.dnsEntries(www.testing.com).dnsResolves = %s", egressDNS.dnsEntries["www.testing.com"].dnsResolves)

		mockDNSOps.AssertExpectations(t)
		//mockExecRunner.AssertExpectations(t)
		//return nil
	}
	//	err = app.Run([]string{app.Name})
	//	assert.Equal(t, err, nil)
	//Expect(err).NotTo(HaveOccurred())
}

//}
