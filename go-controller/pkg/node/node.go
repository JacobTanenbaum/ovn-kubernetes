package node

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewalldns "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/egressfirewall_dns"

	//dnsobjectapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/dnsobject/v1"

	honode "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	//errors "k8s.io/apimachinery/pkg/api/errors"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	//"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

const (
	egressFirewallDNSDefaultDuration = 30 * time.Minute
)

// OvnNode is the object holder for utilities meant for node management
type OvnNode struct {
	name              string
	Kube              kube.Interface
	watchFactory      factory.NodeWatchFactory
	egressFirewallDNS *egressfirewalldns.EgressDNS
	dnsNameNamespaces map[string]map[string]struct{}
	stopChan          chan struct{}
	recorder          record.EventRecorder
	gateway           Gateway
}

// NewNode creates a new controller for node management
func NewNode(ovnClientset *util.OVNClientset, wf factory.NodeWatchFactory, name string, stopChan chan struct{}, eventRecorder record.EventRecorder) *OvnNode {
	return &OvnNode{
		name:         name,
		Kube:         &kube.Kube{KClient: ovnClientset.KubeClient, DNSObjectClient: ovnClientset.DNSObjectClient},
		watchFactory: wf,
		stopChan:     stopChan,
		recorder:     eventRecorder,
	}
}

func setupOVNNode(node *kapi.Node) error {
	var err error

	encapIP := config.Default.EncapIP
	if encapIP == "" {
		encapIP, err = util.GetNodePrimaryIP(node)
		if err != nil {
			return fmt.Errorf("failed to obtain local IP from node %q: %v", node.Name, err)
		}
	} else {
		if ip := net.ParseIP(encapIP); ip == nil {
			return fmt.Errorf("invalid encapsulation IP provided %q", encapIP)
		}
	}

	_, stderr, err := util.RunOVSVsctl("set",
		"Open_vSwitch",
		".",
		fmt.Sprintf("external_ids:ovn-encap-type=%s", config.Default.EncapType),
		fmt.Sprintf("external_ids:ovn-encap-ip=%s", encapIP),
		fmt.Sprintf("external_ids:ovn-remote-probe-interval=%d",
			config.Default.InactivityProbe),
		fmt.Sprintf("external_ids:ovn-openflow-probe-interval=%d",
			config.Default.OpenFlowProbe),
		fmt.Sprintf("external_ids:hostname=\"%s\"", node.Name),
		"external_ids:ovn-monitor-all=true",
	)
	if err != nil {
		return fmt.Errorf("error setting OVS external IDs: %v\n  %q", err, stderr)
	}
	// If EncapPort is not the default tell sbdb to use specified port.
	if config.Default.EncapPort != config.DefaultEncapPort {
		systemID, err := util.GetNodeChassisID()
		if err != nil {
			return err
		}
		uuid, _, err := util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "Encap",
			fmt.Sprintf("chassis_name=%s", systemID))
		if err != nil {
			return err
		}
		if len(uuid) == 0 {
			return fmt.Errorf("unable to find encap uuid to set geneve port for chassis %s", systemID)
		}
		_, stderr, errSet := util.RunOVNSbctl("set", "encap", uuid,
			fmt.Sprintf("options:dst_port=%d", config.Default.EncapPort),
		)
		if errSet != nil {
			return fmt.Errorf("error setting OVS encap-port: %v\n  %q", errSet, stderr)
		}
	}
	return nil
}

func isOVNControllerReady(name string) (bool, error) {
	runDir := util.GetOvnRunDir()

	pid, err := ioutil.ReadFile(runDir + "ovn-controller.pid")
	if err != nil {
		return false, fmt.Errorf("unknown pid for ovn-controller process: %v", err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		ctlFile := runDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSuffix(string(pid), "\n"))
		ret, _, err := util.RunOVSAppctl("-t", ctlFile, "connection-status")
		if err == nil {
			klog.Infof("Node %s connection status = %s", name, ret)
			return ret == "connected", nil
		}
		return false, err
	})
	if err != nil {
		return false, fmt.Errorf("timed out waiting sbdb for node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, _, err := util.RunOVSVsctl("--", "br-exists", "br-int")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out checking whether br-int exists or not on node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		stdout, _, err := util.RunOVSOfctl("dump-aggregate", "br-int")
		if err != nil {
			klog.V(5).Infof("Error dumping aggregate flows: %v "+
				"for node: %s", err, name)
			return false, nil
		}
		ret := strings.Contains(stdout, "flow_count=0")
		if ret {
			klog.V(5).Infof("Got a flow count of 0 when "+
				"dumping flows for node: %s", name)
		}
		return !ret, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out dumping br-int flow entries for node %s: %v", name, err)
	}

	return true, nil
}

// Start learns the subnets assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (n *OvnNode) Start(wg *sync.WaitGroup) error {
	var err error
	var node *kapi.Node
	var subnets []*net.IPNet

	// Setting debug log level during node bring up to expose bring up process.
	// Log level is returned to configured value when bring up is complete.
	var level klog.Level
	if err := level.Set("5"); err != nil {
		klog.Errorf("Setting klog \"loglevel\" to 5 failed, err: %v", err)
	}

	for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
		if err := auth.SetDBAuth(); err != nil {
			return err
		}
	}

	if node, err = n.Kube.GetNode(n.name); err != nil {
		return fmt.Errorf("error retrieving node %s: %v", n.name, err)
	}
	err = setupOVNNode(node)
	if err != nil {
		return err
	}

	_, eferr := n.watchFactory.GetCRD("egressfirewalls.k8s.ovn.org")
	_, dnsOerr := n.watchFactory.GetCRD("dnsobjects.k8s.ovn.org")
	if eferr == nil && dnsOerr == nil {
		klog.Infof("This node is configured with egressfirewall enabled")
		n.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(n.name, n.watchFactory, n.Kube, make(chan struct{}))
		if err != nil {
			return fmt.Errorf("egressfirewall could not start properly on %s", n.name)
		}
		n.egressFirewallDNS.Run(egressFirewallDNSDefaultDuration)
	}

	// First wait for the node logical switch to be created by the Master, timeout is 300s.
	err = wait.PollImmediate(500*time.Millisecond, 300*time.Second, func() (bool, error) {
		if node, err = n.Kube.GetNode(n.name); err != nil {
			klog.Infof("Waiting to retrieve node %s: %v", n.name, err)
			return false, nil
		}
		subnets, err = util.ParseNodeHostSubnetAnnotation(node)
		if err != nil {
			klog.Infof("Waiting for node %s to start, no annotation found on node for subnet: %v", n.name, err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for node's: %q logical switch: %v", n.name, err)
	}

	klog.Infof("Node %s ready for ovn initialization with subnet %s", n.name, util.JoinIPNets(subnets, ","))

	if _, err = isOVNControllerReady(n.name); err != nil {
		return err
	}

	nodeAnnotator := kube.NewNodeAnnotator(n.Kube, node)
	waiter := newStartupWaiter()

	// Initialize management port resources on the node
	mgmtPortConfig, err := createManagementPort(n.name, subnets, nodeAnnotator, waiter)
	if err != nil {
		return err
	}

	// Initialize gateway resources on the node
	if err := n.initGateway(subnets, nodeAnnotator, waiter, mgmtPortConfig); err != nil {
		return err
	}

	if err := nodeAnnotator.Run(); err != nil {
		return fmt.Errorf("failed to set node %s annotations: %v", n.name, err)
	}

	// Wait for management port and gateway resources to be created by the master
	klog.Infof("Waiting for gateway and management port readiness...")
	start := time.Now()
	if err := waiter.Wait(); err != nil {
		return err
	}
	go n.gateway.Run(n.stopChan, wg)
	klog.Infof("Gateway and management port readiness took %v", time.Since(start))

	if config.HybridOverlay.Enabled {
		nodeController, err := honode.NewNode(
			n.Kube,
			n.name,
			n.watchFactory.NodeInformer(),
			n.watchFactory.LocalPodInformer(),
			informer.NewDefaultEventHandler,
		)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			nodeController.Run(n.stopChan)
		}()
	}

	if err := level.Set(strconv.Itoa(config.Logging.Level)); err != nil {
		klog.Errorf("Reset of initial klog \"loglevel\" failed, err: %v", err)
	}

	// start health check to ensure there are no stale OVS internal ports
	go checkForStaleOVSInterfaces(n.stopChan)

	// start management port health check
	go checkManagementPortHealth(mgmtPortConfig, n.stopChan)

	confFile := filepath.Join(config.CNI.ConfDir, config.CNIConfFileName)
	_, err = os.Stat(confFile)
	if os.IsNotExist(err) {
		err = config.WriteCNIConfig()
		if err != nil {
			return err
		}
	}

	n.watchFactory.InitializeEgressFirewallWatchFactory()
	n.WatchEndpoints()
	n.WatchEgressFirewalls()

	cniServer := cni.NewCNIServer("", n.watchFactory)
	err = cniServer.Start(cni.HandleCNIRequest)

	return err
}

//KEYWORD: TODO (jtanenba) should I be watching CRDS Watching DNSObjects to reconcile?
func (n *OvnNode) WatchEgressFirewalls() {
	n.watchFactory.AddEgressFirewallHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Printf("KEYWORD: THIS IS STARTING TO WORK\n\n\n")
			// grab just the DNSNames from the egressFirewall (and namespace)
			egressFirewall := obj.(*egressfirewall.EgressFirewall)
			var dnsNames []string

			// loop through all rules
			for _, rule := range egressFirewall.Spec.Egress {
				//we only care if there are DNSNames associated with the egressFirewall Rule
				if len(rule.To.DNSName) > 0 {
					dnsNames = append(dnsNames, rule.To.DNSName)

				}
			}
			n.egressFirewallDNS.Add(dnsNames, egressFirewall.Namespace)

		},
		UpdateFunc: func(old, newer interface{}) {
			// What can happen on an update?
			// an egressFirewall adds a dnsName in which case it should call n.egressFirewallDNS.Add()
			// an egressFirewall removes a dnsName in which case there should be an n.egressFirewallDNS.Remove
			// thats it compare the old and new objects
			// if there is a dnsName in the newer that is not in old - call Delete()
			// if there is a dnsName in the old but not in newer - call Delete() Remove should deal with only the namespace or the actual thing...
			newerEgressFirewall := newer.(*egressfirewall.EgressFirewall)
			olderEgressFirewall := old.(*egressfirewall.EgressFirewall)
			newerDNSNames := make(map[string]struct{})
			olderDNSNames := make(map[string]struct{})
			// get all the dnsNames in the new version of the egressFirewall
			klog.Infof("Updating EgressFirewall %s in namespace %s", newerEgressFirewall.Name, newerEgressFirewall.Namespace)
			for _, rule := range newerEgressFirewall.Spec.Egress {
				if len(rule.To.DNSName) > 0 {
					newerDNSNames[rule.To.DNSName] = struct{}{}

				}
			}
			// get all the dnsNames from the old version of the egressfirewall
			for _, rule := range olderEgressFirewall.Spec.Egress {
				olderDNSNames[rule.To.DNSName] = struct{}{}
			}
			// to the node the only thing that matters is the presence of the dnsName in order to resolve, unlike on the master the order does not matter
			// shortcut in case something else changes on the egressFirewall besides the dnsNames
			if reflect.DeepEqual(newerDNSNames, olderDNSNames) {
				return
			}

			var dnsNamesToAdd []string
			var dnsNamesToRemove []string
			for newDNSName, _ := range newerDNSNames {
				if _, exists := olderDNSNames[newDNSName]; !exists {
					// the dnsName is present in the new version but not in the old so it needs to be added to the dns resolver
					dnsNamesToAdd = append(dnsNamesToAdd, newDNSName)
				}
			}
			for oldDNSName, _ := range olderDNSNames {
				// the dnsName is present in the old version but not in the new version so it needs to be removed from the resolver
				if _, exists := newerDNSNames[oldDNSName]; !exists {
					dnsNamesToRemove = append(dnsNamesToRemove, oldDNSName)
				}
			}
			n.egressFirewallDNS.Add(dnsNamesToAdd, newerEgressFirewall.Namespace)
			fmt.Printf("KEYWORD: DNSNAMES TO REMOVE-- %+v\n", dnsNamesToRemove)
			n.egressFirewallDNS.Remove(dnsNamesToRemove, newerEgressFirewall.Namespace)

		},
		DeleteFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall)
			klog.Infof("Deleteing EgressFirewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)
			var dnsNames []string
			for _, rule := range egressFirewall.Spec.Egress {
				if len(rule.To.DNSName) > 0 {
					dnsNames = append(dnsNames, rule.To.DNSName)
				}
			}
			n.egressFirewallDNS.Remove(dnsNames, egressFirewall.Namespace)

		},
	}, nil)

}

func (n *OvnNode) WatchEndpoints() {
	n.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			epNew := new.(*kapi.Endpoints)
			epOld := old.(*kapi.Endpoints)
			newEpAddressMap := buildEndpointAddressMap(epNew.Subsets)
			for item := range buildEndpointAddressMap(epOld.Subsets) {
				if _, ok := newEpAddressMap[item]; !ok {
					err := deleteConntrack(item.ip, item.port, item.protocol)
					if err != nil {
						klog.Errorf("Failed to delete conntrack entry for %s: %v", item.ip, err)
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			for item := range buildEndpointAddressMap(ep.Subsets) {
				err := deleteConntrack(item.ip, item.port, item.protocol)
				if err != nil {
					klog.Errorf("Failed to delete conntrack entry for %s: %v", item.ip, err)
				}

			}
		},
	}, nil)
}

type epAddressItem struct {
	ip       string
	port     int32
	protocol kapi.Protocol
}

//buildEndpointAddressMap builds a map of all UDP and SCTP ports in the endpoint subset along with that port's IP address
func buildEndpointAddressMap(epSubsets []kapi.EndpointSubset) map[epAddressItem]struct{} {
	epMap := make(map[epAddressItem]struct{})
	for _, subset := range epSubsets {
		for _, address := range subset.Addresses {
			for _, port := range subset.Ports {
				if port.Protocol == kapi.ProtocolUDP || port.Protocol == kapi.ProtocolSCTP {
					epMap[epAddressItem{
						ip:       address.IP,
						port:     port.Port,
						protocol: port.Protocol,
					}] = struct{}{}
				}
			}
		}
	}

	return epMap
}
