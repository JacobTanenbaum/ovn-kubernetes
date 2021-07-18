package addressset

import (
	"fmt"
	"net"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

type testAddressSetName struct {
	namespace string
	suffix1   string
	suffix2   string
	//each suffix in turn
	suffix []string
	remove bool
}

const (
	addrsetName = "foobar"
	ipAddress1  = "1.2.3.4"
	ipAddress2  = "5.6.7.8"
	fakeUUID    = "8a86f6d8-7972-4253-b0bd-ddbef66e9303"
	fakeUUIDv6  = "8a86f6d8-7972-4253-b0bd-ddbef66e9304"
)

func (asn *testAddressSetName) makeName() string {
	return fmt.Sprintf("%s.%s.%s", asn.namespace, asn.suffix1, asn.suffix2)
}

func (asn *testAddressSetName) makeNames() string {
	output := asn.namespace
	for _, suffix := range asn.suffix {
		output = output + "." + suffix
	}
	return output

}

var _ = ginkgo.Describe("OVN Address Set operations", func() {
	var (
		app       *cli.App
		fexec     *ovntest.FakeExec
		asFactory AddressSetFactory
		stopChan  chan struct{}
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		stopChan = make(chan struct{})

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fexec = ovntest.NewFakeExec()

	})

	ginkgo.JustBeforeEach(func() {
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.AfterEach(func() {
		close(stopChan)
	})

	ginkgo.Context("when iterating address sets", func() {
		ginkgo.It("calls the iterator function for each address set with the given prefix", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						&nbdb.AddressSet{
							Name:        "1",
							ExternalIDs: map[string]string{"name": "ns1.foo.bar"},
						},
						&nbdb.AddressSet{
							Name:        "2",
							ExternalIDs: map[string]string{"name": "ns2.test.test2"},
						},

						&nbdb.AddressSet{
							Name:        "3",
							ExternalIDs: map[string]string{"name": "ns3"},
						},
					},
				}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				namespaces := []testAddressSetName{
					{
						namespace: "ns1",
						suffix:    []string{"foo", "bar"},
					},
					{
						namespace: "ns2",
						suffix:    []string{"test", "test2"},
					},
					{
						namespace: "ns3",
					},
				}

				err = asFactory.ProcessEachAddressSet(func(addrSetName, namespaceName, nameSuffix string) {
					found := false
					for _, n := range namespaces {
						name := n.makeNames()
						if addrSetName == name {
							found = true
							gomega.Expect(namespaceName).To(gomega.Equal(n.namespace))
						}
					}
					gomega.Expect(found).To(gomega.BeTrue())
				})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("when creating an address set object", func() {
		ginkgo.It("re-uses an existing address set and replaces IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
				)
				dbSetup := libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						&nbdb.AddressSet{
							UUID:        "",
							Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
							ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
							Addresses:   []string{"10.10.10.10"},
						},
					},
				}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				expectedDatabaseState := &nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   []string{ipAddress1, ipAddress2},
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				addrSetList := &[]nbdb.AddressSet{}
				libovsdbOvnNBClient.List(addrSetList)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("clears an existing address set of IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						&nbdb.AddressSet{
							UUID:        "",
							Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
							ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
							Addresses:   []string{"10.10.10.10"},
						},
					},
				}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				_, err = config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)
				_, err = asFactory.NewAddressSet("foobar", nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState := &nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   nil,
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("creates a new address set and sets IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				expectedDatabaseState := &nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   []string{ipAddress1, ipAddress2},
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				}

				_, err = asFactory.NewAddressSet(addrsetName, []net.IP{net.ParseIP(ipAddress1), net.ParseIP(ipAddress2)})
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.It("destroys an address set", func() {
		app.Action = func(ctx *cli.Context) error {
			dbSetup := libovsdbtest.TestSetup{}
			libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

			_, err = config.InitConfig(ctx, fexec, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			as, err := asFactory.NewAddressSet(addrsetName, []net.IP{net.ParseIP(ipAddress1), net.ParseIP(ipAddress2)})

			err = as.Destroy()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			expectedDatabaseState := []libovsdbtest.TestData{}
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.Context("when manipulating IPs in an address set object", func() {
		ginkgo.It("adds an IP to an empty address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				as, err := asFactory.NewAddressSet("foobar", nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = as.AddIPs([]net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				expectedDatabaseState := &nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   []string{addr1},
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("deletes an IP from an address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)
				as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Deleting a non-existent address is a no-op
				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState := &nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   nil,
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("sets an already set addressSet", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"
				const addr2 string = "2.3.4.5"
				const addr3 string = "7.8.9.10"

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)
				as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = as.SetIPs([]net.IP{net.ParseIP(addr2), net.ParseIP(addr3)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   []string{addr2, addr3},
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
				}

				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("Dual stack : when creating an address set object", func() {
		ginkgo.It("re-uses an existing dual stack address set and replaces IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
					addr3 string = "2001:db8::1"
					addr4 string = "2001:db8::2"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
					net.ParseIP(addr3), net.ParseIP(addr4)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   []string{addr1, addr2},
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   []string{addr3, addr4},
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("clears an existing address set of dual stack IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
					addr3 string = "2001:db8::1"
					addr4 string = "2001:db8::2"
				)
				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
					net.ParseIP(addr3), net.ParseIP(addr4)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				_, err = asFactory.NewAddressSet("foobar", nil)
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("creates a new address set and sets dual stack IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
					addr3 string = "2001:db8::1"
					addr4 string = "2001:db8::2"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
					net.ParseIP(addr3), net.ParseIP(addr4)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   []string{addr1, addr2},
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   []string{addr3, addr4},
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.It("destroys an dual stack address set", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				addr1 string = "1.2.3.4"
				addr2 string = "5.6.7.8"
				addr3 string = "2001:db8::1"
				addr4 string = "2001:db8::2"
			)
			_, err := config.InitConfig(ctx, fexec, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			config.IPv6Mode = true

			dbSetup := libovsdbtest.TestSetup{}
			libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

			as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
				net.ParseIP(addr3), net.ParseIP(addr4)})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			expectedDatabaseState := []libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
					Addresses:   []string{addr1, addr2},
					ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
				},
				&nbdb.AddressSet{
					Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
					Addresses:   []string{addr3, addr4},
					ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
				},
			}
			gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))

			err = as.Destroy()
			expectedDatabaseState = []libovsdbtest.TestData{}
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
			addrSetList := &[]nbdb.AddressSet{}
			libovsdbOvnNBClient.List(addrSetList)
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.Context("Dual Stack : when manipulating IPs in an address set object", func() {
		ginkgo.It("adds IP to an empty dual stack address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"
				const addr2 string = "2001:db8::1"

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				as, err := asFactory.NewAddressSet("foobar", nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))

				err = as.AddIPs([]net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   []string{addr1},
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   []string{addr2},
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Re-adding is a no-op
				err = as.AddIPs([]net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("deletes an IP from an dual stack address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"
				const addr2 string = "2001:db8::1"

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				dbSetup := libovsdbtest.TestSetup{}
				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)
				as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   []string{addr1},
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   []string{addr2},
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))

				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv4AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv4AddressSetSuffix},
					},
					&nbdb.AddressSet{
						Name:        hashedAddressSet(addrsetName + ipv6AddressSetSuffix),
						Addresses:   nil,
						ExternalIDs: map[string]string{"name": addrsetName + ipv6AddressSetSuffix},
					},
				}
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))

				// Deleting a non-existent address is a no-op
				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("Dual Stack : when cleaning up old address sets", func() {
		ginkgo.BeforeEach(func() {
			fexec = ovntest.NewLooseCompareFakeExec()
		})

		ginkgo.It("destroys address sets in old non dual stack format", func() {
			app.Action = func(ctx *cli.Context) error {
				namespaces := []testAddressSetName{
					{
						// to be removed as v4 address exists
						namespace: "as1",
						remove:    true,
					},
					{
						// to be removed as v6 address exists
						namespace: "as2",
						remove:    true,
					},
					{
						// to be removed as both v4 & v6 address exists
						namespace: "as3",
						remove:    true,
					},
					{
						// not to be removed, no v4 or v6 address exists
						namespace: "as4",
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as1",
						suffix2:   ipv4AddressSetSuffix,
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as2",
						suffix2:   ipv6AddressSetSuffix,
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as3",
						suffix2:   ipv4AddressSetSuffix,
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as3",
						suffix2:   ipv6AddressSetSuffix,
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as5",
						suffix2:   ipv4AddressSetSuffix,
					},
					{
						// not to be removed, address in new dual stack format
						namespace: "as5",
						suffix2:   ipv6AddressSetSuffix,
					},
				}
				expectedDatabaseState := []libovsdbtest.TestData{}

				dbSetup := libovsdbtest.TestSetup{}
				for _, n := range namespaces {
					dbSetup.NBData = append(dbSetup.NBData, &nbdb.AddressSet{
						Name:        hashedAddressSet(n.namespace + n.suffix2),
						ExternalIDs: map[string]string{"name": n.namespace + n.suffix2},
					})
					if !n.remove {
						expectedDatabaseState = append(expectedDatabaseState, &nbdb.AddressSet{
							Name:        hashedAddressSet(n.namespace + n.suffix2),
							ExternalIDs: map[string]string{"name": n.namespace + n.suffix2},
						})
					}
				}

				_, err := config.InitConfig(ctx, fexec, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.IPv6Mode = true

				libovsdbOvnNBClient, _, err := libovsdbtest.NewNBSBTestHarness(dbSetup, stopChan)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				asFactory = NewOvnAddressSetFactory(libovsdbOvnNBClient)

				err = NonDualStackAddressSetCleanup(libovsdbOvnNBClient)
				gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveTestDataIgnoringUUIDs(expectedDatabaseState))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
				addrSetList := &[]nbdb.AddressSet{}
				libovsdbOvnNBClient.List(addrSetList)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
})
