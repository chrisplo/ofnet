/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ofnet

import (
	"fmt"
	"net"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ovsdbDriver"
)

func TestPolicyAddDelete(t *testing.T) {
	var resp bool
	rpcPort := uint16(9600)
	ovsPort := uint16(9601)
	lclIP := net.ParseIP("10.10.10.10")
	ofnetAgent, err := NewOfnetAgent("", "vrouter", lclIP, rpcPort, ovsPort, nil)
	if err != nil {
		t.Fatalf("Error creating ofnet agent. Err: %v", err)
	}

	defer func() { ofnetAgent.Delete() }()

	// Override MyAddr to local host
	ofnetAgent.MyAddr = "127.0.0.1"

	// Create a Master
	ofnetMaster := NewOfnetMaster("", uint16(9602))

	defer func() { ofnetMaster.Delete() }()

	masterInfo := OfnetNode{
		HostAddr: "127.0.0.1",
		HostPort: uint16(9602),
	}

	// connect vrtr agent to master
	err = ofnetAgent.AddMaster(&masterInfo, &resp)
	if err != nil {
		t.Errorf("Error adding master %+v. Err: %v", masterInfo, err)
	}

	log.Infof("Created vrouter ofnet agent: %v", ofnetAgent)

	brName := "ovsbr60"
	ovsDriver := ovsdbDriver.NewOvsDriver(brName)
	err = ovsDriver.AddController("127.0.0.1", ovsPort)
	if err != nil {
		t.Fatalf("Error adding controller to ovs: %s", brName)
	}

	// Wait for switch to connect to controller
	ofnetAgent.WaitForSwitchConnection()

	// Create a vlan for the endpoint
	ofnetAgent.AddNetwork(1, 1, "", "default")
	ofnetAgent.AddNetwork(2, 2, "", "second")
	ofnetAgent.AddNetwork(4, 4, "", "third")
	ofnetAgent.AddNetwork(8, 8, "", "fourth")

	macAddr, _ := net.ParseMAC("00:01:02:03:04:05")
	endpoint := EndpointInfo{
		EndpointGroup: 100,
		PortNo:        12,
		MacAddr:       macAddr,
		Vlan:          1,
		IpAddr:        net.ParseIP("10.2.2.2"),
	}

	log.Infof("Adding Local endpoint: %+v", endpoint)

	// Add an Endpoint
	err = ofnetAgent.AddLocalEndpoint(endpoint)
	if err != nil {
		t.Errorf("Error adding endpoint. Err: %v", err)
		return
	}

	tcpRule := &OfnetPolicyRule{
		RuleId:           "tcpRule",
		Priority:         100,
		SrcEndpointGroup: 100,
		DstEndpointGroup: 200,
		SrcIpAddr:        "10.10.10.10/24",
		DstIpAddr:        "10.1.1.1/24",
		SrcTenant:        "default",
		DstTenant:        "second",
		IpProtocol:       6,
		DstPort:          100,
		SrcPort:          200,
		Action:           "allow",
	}

	log.Infof("Adding rule: %+v", tcpRule)

	// Add a policy
	err = ofnetMaster.AddRule(tcpRule)
	if err != nil {
		t.Errorf("Error installing tcpRule {%+v}. Err: %v", tcpRule, err)
		return
	}

	udpRule := &OfnetPolicyRule{
		RuleId:           "udpRule",
		Priority:         100,
		SrcEndpointGroup: 300,
		DstEndpointGroup: 400,
		SrcIpAddr:        "20.20.20.20/24",
		DstIpAddr:        "20.2.2.2/24",
		IpProtocol:       17,
		SrcTenant:        "third",
		DstTenant:        "fourth",
		DstPort:          300,
		SrcPort:          400,
		Action:           "deny",
	}

	log.Infof("Adding rule: %+v", udpRule)

	// Add the policy
	err = ofnetMaster.AddRule(udpRule)
	if err != nil {
		t.Errorf("Error installing udpRule {%+v}. Err: %v", udpRule, err)
		return
	}

	// tenant second is allowed to talk to group in tenant third
	tenantIngressRule := &OfnetPolicyRule{
		RuleId:           "tenantIngressRule",
		Priority:         50,
		DstEndpointGroup: 400,
		IpProtocol:       6,
		SrcTenant:        "second",
		DstTenant:        "third",
		Action:           "allow",
	}
	log.Infof("Adding tenant ingress rule: %+v", udpRule)
	err = ofnetMaster.AddRule(tenantIngressRule)
	if err != nil {
		t.Errorf("Error installing tenant ingress rule {%+v}. Err: %v", tenantIngressRule, err)
		return
	}

	// Get all the flows
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}
	log.Infof("Flow dump:")
	log.Infof("==========")
	for _, f := range flowList {
		log.Infof("%+v", f)
	}

	// verify src group flow
	// tenant+group: format((1<<(1+30+16))+(100<<(1+30)), 'x')
	// tenant mask: (((1<<14))-1)<<(1+30+16) = 2305702271725338624
	// group mask: (((1<<16))-1)<<(30+1) = 140735340871680
	// mask: format(2305702271725338624 + 140735340871680, 'x')
	srcGrpFlowMatch := fmt.Sprintf("priority=10,in_port=12 actions=write_metadata:0x803200000000/0x1fffffff80000000")
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, srcGrpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", srcGrpFlowMatch, brName)
	}
	log.Infof("Found src group %s on ovs %s", srcGrpFlowMatch, brName)

	// verify dst group flow
	// tenant+group: format((1<<(1+16))+(100<<1), 'x')
	// tenant mask: (((1<<14))-1)<<(1+16) = 2147352576
	// group mask: (((1<<16))-1)<<1 = 131070
	// mask: format(2147352576 + 131070, 'x')
	dstGrpFlowMatch := fmt.Sprintf("priority=100,ip,nw_dst=10.2.2.2 actions=write_metadata:0x200c8/0x7ffffffe")
	if !ofctlFlowMatch(flowList, DST_GRP_TBL_ID, dstGrpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", dstGrpFlowMatch, brName)
	}
	log.Infof("Found dst group %s on ovs %s", dstGrpFlowMatch, brName)

	// source tenant mask: (((1<<14))-1)<<(1+30+16) = 2305702271725338624
	// source group mask: ( (1<<16) -1 )<<(30+1) = 140735340871680
	// dest tenant mask: (((1<<14))-1)<<(1+16) = 2147352576
	// dest group mask: ( (1<<16) -1 )<<1 = 131070
	// mask: format(2305702271725338624 + 140735340871680 + 2147352576 + 131070, 'x')
	metadataMask := "0x1ffffffffffffffe"

	// verify tcp rule flow entry exists
	// tenant 1 group 100 source + tenant 2 group 200 dest:
	//   format( (1<<(1+30+16)) + (100<<(30+1)) + (2<<(1+16)) + (200<<1) , 'x')
	tcpFlowMatch := fmt.Sprintf("priority=110,tcp,metadata=0x803200040190/%s,nw_src=10.10.10.0/24,nw_dst=10.1.1.0/24,tp_src=200,tp_dst=100", metadataMask)
	if !ofctlFlowMatch(flowList, POLICY_TBL_ID, tcpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", tcpFlowMatch, brName)
	}
	log.Infof("Found tcp rule %s on ovs %s", tcpFlowMatch, brName)

	// verify udp rule flow
	// tenant 3 group 300 source + tenant 4 group 400 dest:
	//   format( (3<<(1+30+16)) + (300<<(30+1)) + (4<<(1+16)) + (400<<1) , 'x')
	udpFlowMatch := fmt.Sprintf("priority=110,udp,metadata=0x1809600080320/%s,nw_src=20.20.20.0/24,nw_dst=20.2.2.0/24,tp_src=400,tp_dst=300", metadataMask)
	if !ofctlFlowMatch(flowList, POLICY_TBL_ID, udpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", udpFlowMatch, brName)
	}
	log.Infof("Found udp rule %s on ovs %s", udpFlowMatch, brName)

	// source tenant mask: (((1<<14))-1)<<(1+30+16) = 2305702271725338624
	// dest tenant mask: (((1<<14))-1)<<(1+16) = 2147352576
	// dest group mask: ( (1<<16) -1 )<<1 = 131070
	// mask: format(2305702271725338624 + 2147352576 + 131070, 'x')
	fromTenantMetadataMask := "0x1fff80007ffffffe"

	// verify tenant ingress rule flow
	// tenant 2 source + tenant 3 group 400 dest:
	//   format( (2<<(1+30+16)) + (3<<(1+16)) + (400<<1) , 'x')
	tenantIngressFlowMatch := fmt.Sprintf("priority=60,tcp,metadata=0x1000000060320/%s", fromTenantMetadataMask)
	if !ofctlFlowMatch(flowList, POLICY_TBL_ID, tenantIngressFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", tenantIngressFlowMatch, brName)
	}
	log.Infof("Found udp rule %s on ovs %s", tenantIngressFlowMatch, brName)

	// verify output flow
	outputFlowMatch := fmt.Sprintf("priority=100,ip,nw_dst=10.2.2.2")
	if !ofctlFlowMatch(flowList, IP_TBL_ID, outputFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", outputFlowMatch, brName)
	}
	log.Infof("Found src group %s on ovs %s", outputFlowMatch, brName)

	// Delete policies
	err = ofnetMaster.DelRule(tcpRule)
	if err != nil {
		t.Fatalf("Error deleting tcpRule {%+v}. Err: %v", tcpRule, err)
	}
	err = ofnetMaster.DelRule(udpRule)
	if err != nil {
		t.Fatalf("Error deleting udpRule {%+v}. Err: %v", udpRule, err)
	}
	err = ofnetAgent.RemoveLocalEndpoint(endpoint.PortNo)
	if err != nil {
		t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
	}

	log.Infof("Deleted all policy entries")

	// Get the flows again
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Fatalf("Error getting flow entries. Err: %v", err)
	}

	// Make sure flows are gone
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, srcGrpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", srcGrpFlowMatch, brName)
	}
	if ofctlFlowMatch(flowList, DST_GRP_TBL_ID, dstGrpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", dstGrpFlowMatch, brName)
	}
	if ofctlFlowMatch(flowList, POLICY_TBL_ID, tcpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", tcpFlowMatch, brName)
	}
	if ofctlFlowMatch(flowList, POLICY_TBL_ID, udpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", udpFlowMatch, brName)
	}

	log.Infof("Verified all flows are deleted")
}
