package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

type TagList []string

func (tags TagList) Contains(tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (tags TagList) ContainsMatchingPrefix(prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

func (tags TagList) ContainsAny(other TagList) bool {
	for _, tag := range other {
		if tags.Contains(tag) {
			return true
		}
	}
	return false
}

type ReplaceFunc func(string) (string, error)

type NetHandler interface {
	HandleConn(network string, ip net.IP, port uint16, conn net.Conn)
}

type FlowListener interface {
	AcceptConn(target Instance, service Service, conn net.Conn)
}

type FuncFlowListener func(Instance, Service, net.Conn)

// AcceptConn implements FlowListener.
func (f FuncFlowListener) AcceptConn(target Instance, service Service, conn net.Conn) {
	f(target, service, conn)
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

type Service struct {
	Name string
	Port int
	Tags TagList
}

type FlowHandler struct {
	ParsedFlow
	FlowListener
}

type Instance interface {
	Id() string
	Tags() TagList
	IP() net.IP
	Services() []Service
	Flows() []FlowHandler
}

type flowRouterHandler func(network string, ip net.IP, port uint16, conn net.Conn)

// HandleConn implements NetHandler.
func (f flowRouterHandler) HandleConn(network string, ip net.IP, port uint16, conn net.Conn) {
	f(network, ip, port, conn)
}

var (
	_ NetHandler = flowRouterHandler(nil)
)

type FlowRouter struct {
	instances map[string]Instance
}

func (r *FlowRouter) handleConnection(source Instance, target Instance, service Service, conn net.Conn) bool {
	// Iterate though each flow.
	for _, flow := range source.Flows() {
		// Check if the source tags match.
		if !source.Tags().ContainsAny(source.Tags()) {
			slog.Info("rejected source", "flow", flow.ParsedFlow, "source", source.Id(), "target", target.Id(), "service", service.Name)
			continue
		}

		// Check if the target tags match.
		if flow.ParsedFlow.Instance == "*" {
			if !target.Tags().ContainsMatchingPrefix(fmt.Sprintf("%s/", flow.ParsedFlow.Tag)) {
				slog.Info("rejected target partial", "flow", flow.ParsedFlow, "source", source.Id(), "target", target.Id(), "targetTags", target.Tags())
				continue
			}
		} else if !target.Tags().Contains(fmt.Sprintf("%s/%s", flow.ParsedFlow.Tag, flow.ParsedFlow.Instance)) {
			slog.Info("rejected target", "flow", flow.ParsedFlow, "source", source.Id(), "target", target.Id(), "targetTags", target.Tags())
			continue
		}

		// Check if the service tags match.
		if !service.Tags.Contains(flow.ParsedFlow.Service) {
			slog.Info("rejected service", "flow", flow.ParsedFlow, "source", source.Id(), "target", target.Id(), "service", service.Name)
			continue
		}

		// We have a match, accept the connection.
		flow.FlowListener.AcceptConn(target, service, conn)
		return true
	}
	// slog.Info("no matching flow", "source", source.Id(), "target", target.Id(), "service", service.Name)
	return false
}

func (r *FlowRouter) AddInstance(instance Instance) (NetHandler, error) {
	if _, ok := r.instances[instance.Id()]; ok {
		return nil, fmt.Errorf("instance already exists: %s", instance.Id())
	}

	r.instances[instance.Id()] = instance

	return flowRouterHandler(func(network string, ip net.IP, port uint16, conn net.Conn) {
		// find the target by IP
		for _, target := range r.instances {
			if target.IP().Equal(ip) {
				// We found the target, now find the service.
				for _, service := range target.Services() {
					if service.Port == int(port) {
						// We now know instance is trying to connect to target:service.
						if r.handleConnection(instance, target, service, conn) {
							return
						}
					}
				}
			}
		}

		// slog.Info("no matching target", "source", instance.Id(), "ip", ip, "port", port)

		// If we reach here, we couldn't find the target.
		// TODO(joshua): Handle a default route.
		conn.Close()
	}), nil
}

func NewFlowRouter() *FlowRouter {
	return &FlowRouter{
		instances: make(map[string]Instance),
	}
}