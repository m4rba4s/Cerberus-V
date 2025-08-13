// SPDX-License-Identifier: Apache-2.0
// Temporary protobuf stub for testing

package main

// Temporary protobuf message stubs for testing
type AddRuleRequest struct {
	Rule *Rule
}

type Rule struct {
	Id          string
	Action      string
	SrcIp       string
	DstIp       string
	SrcPort     int32
	DstPort     int32
	Protocol    string
	Direction   string
	Priority    int32
	Enabled     bool
	Description string
}

type RuleResponse struct {
	Success bool
	Message string
	RuleId  string
}

type DeleteRuleRequest struct {
	RuleId string
}

type StatusResponse struct {
	Success bool
	Message string
}

type Empty struct{}

type Statistics struct {
	TotalPackets   uint64
	TotalBytes     uint64
	DroppedPackets uint64
	AllowedPackets uint64
	ActiveRules    int32
	Uptime         int64
}

type Event struct {
	Id        string
	Type      string
	Timestamp int64
	Source    string
	Target    string
	Protocol  string
	Port      int32
	Message   string
	Severity  string
}

type RulesResponse struct {
	Rules []*Rule
	Count int32
}

// Temporary gRPC server interface stub
type UnimplementedFirewallControlServer struct{}

func (s *UnimplementedFirewallControlServer) AddRule(req *AddRuleRequest) (*RuleResponse, error) {
	return nil, nil
}

func (s *UnimplementedFirewallControlServer) DeleteRule(req *DeleteRuleRequest) (*StatusResponse, error) {
	return nil, nil
}

func (s *UnimplementedFirewallControlServer) GetStats(req *Empty) (*Statistics, error) {
	return nil, nil
}

func (s *UnimplementedFirewallControlServer) GetRules(req *Empty) (*RulesResponse, error) {
	return nil, nil
}

// Temporary interface for testing
type FirewallControlServer interface {
	AddRule(*AddRuleRequest) (*RuleResponse, error)
	DeleteRule(*DeleteRuleRequest) (*StatusResponse, error)
	GetStats(*Empty) (*Statistics, error)
	GetRules(*Empty) (*RulesResponse, error)
}

func RegisterFirewallControlServer(server interface{}, impl FirewallControlServer) {
	// Stub for testing
} 