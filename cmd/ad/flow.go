package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/tinyrange/wireguard"
)

type ReplaceFunc func(string) (string, error)

type FlowListener interface {
	AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn)
}

type FuncFlowListener func(FlowInstance, FlowInstance, FlowService, net.Conn)

// AcceptConn implements FlowListener.
func (f FuncFlowListener) AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
	f(source, target, service, conn)
}

var (
	_ FlowListener = FuncFlowListener(nil)
)

// Flows are formatted as "tag/instance:service".
type ParsedFlow struct {
	Tag      string
	Instance string
	Service  string
}

func ParseFlow(flow string, replace ReplaceFunc) (ParsedFlow, error) {
	parts := strings.Split(flow, ":")
	if len(parts) != 2 {
		return ParsedFlow{}, fmt.Errorf("invalid flow: %s", flow)
	}

	tagParts := strings.Split(parts[0], "/")
	if len(tagParts) == 2 {
		if strings.HasPrefix(tagParts[1], "{") {
			if !strings.HasSuffix(tagParts[1], "}") {
				return ParsedFlow{}, fmt.Errorf("invalid tag: %s", tagParts[1])
			}
			if replace == nil {
				return ParsedFlow{}, fmt.Errorf("replace function required for dynamic instance")
			}
			tag := tagParts[1][1 : len(tagParts[1])-1]
			replaceStr, err := replace(tag)
			if err != nil {
				return ParsedFlow{}, err
			}
			tagParts[1] = replaceStr
		}

		return ParsedFlow{
			Tag:      tagParts[0],
			Instance: tagParts[1],
			Service:  parts[1],
		}, nil
	} else {
		return ParsedFlow{}, fmt.Errorf("invalid flow: %s", flow)
	}
}

func (flow ParsedFlow) String() string {
	if flow.Instance == "" {
		return fmt.Sprintf("%s:%s", flow.Tag, flow.Service)
	}
	return fmt.Sprintf("%s/%s:%s", flow.Tag, flow.Instance, flow.Service)
}

type FlowList []string

func (flows FlowList) Parse(replace ReplaceFunc) ([]ParsedFlow, error) {
	var parsedFlows []ParsedFlow

	for _, flow := range flows {
		parsedFlow, err := ParseFlow(flow, replace)
		if err != nil {
			return nil, err
		}
		parsedFlows = append(parsedFlows, parsedFlow)
	}

	return parsedFlows, nil
}

type FlowService interface {
	FlowListener
	Name() string
	Port() int
	Tags() TagList
}

type FlowInstance interface {
	Hostname() string
	Tags() TagList
	InstanceAddress() net.IP
	Services() []FlowService
	Flows() []ParsedFlow
}

type flowRouterHandler func(network string, ip net.IP, port uint16, conn net.Conn)

// HandleConn implements NetHandler.
func (f flowRouterHandler) HandleConn(network string, ip net.IP, port uint16, conn net.Conn) {
	f(network, ip, port, conn)
}

var (
	_ wireguard.NetHandler = flowRouterHandler(nil)
)

type FlowRouter struct {
	instances map[string]FlowInstance
}

func (r *FlowRouter) handleConnection(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) bool {
	// Iterate though each flow.
	for _, flow := range source.Flows() {
		// Check if the source tags match.
		if !source.Tags().ContainsAny(source.Tags()) {
			// slog.Info("rejected source", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name)
			continue
		}

		// Check if the target tags match.
		if flow.Instance == "*" {
			if !target.Tags().ContainsMatchingPrefix(fmt.Sprintf("%s/", flow.Tag)) {
				// slog.Info("rejected target partial", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
				continue
			}
		} else if !target.Tags().Contains(fmt.Sprintf("%s/%s", flow.Tag, flow.Instance)) {
			// slog.Info("rejected target", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
			continue
		}

		// Check if the service tags match.
		if !service.Tags().Contains(flow.Service) {
			// slog.Info("rejected service", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name)
			continue
		}

		// We have a match, accept the connection.
		service.AcceptConn(source, target, service, conn)
		return true
	}
	// slog.Info("no matching flow", "source", source.InstanceId(), "target", target.InstanceId(), "service", service.Name)
	return false
}

func (r *FlowRouter) AddInstance(instance FlowInstance) (wireguard.NetHandler, error) {
	if _, ok := r.instances[instance.InstanceId()]; ok {
		return nil, fmt.Errorf("instance already exists: %s", instance.InstanceId())
	}

	r.instances[instance.InstanceId()] = instance

	return flowRouterHandler(func(network string, ip net.IP, port uint16, conn net.Conn) {
		// find the target by IP
		for _, target := range r.instances {
			if target.InstanceAddress().Equal(ip) {
				// We found the target, now find the service.
				for _, service := range target.Services() {
					if service.Port() == int(port) {
						// We now know instance is trying to connect to target:service.
						if r.handleConnection(instance, target, service, conn) {
							return
						}
					}
				}
			}
		}

		// slog.Info("no matching target", "source", instance.InstanceId(), "ip", ip, "port", port)

		// If we reach here, we couldn't find the target.
		// TODO(joshua): Handle a default route.
		conn.Close()
	}), nil
}

func NewFlowRouter() *FlowRouter {
	return &FlowRouter{
		instances: make(map[string]FlowInstance),
	}
}
