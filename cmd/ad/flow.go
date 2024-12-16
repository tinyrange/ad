package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/tinyrange/wireguard"
)

type NetHandler interface {
	wireguard.NetHandler
	Hostname() string
	String() string
	IpAddress() net.IP
}

type ReplaceFunc func(string) (string, error)

type FlowListener interface {
	AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn)
	DialContext(ctx context.Context, target FlowInstance) (net.Conn, error)
}

type FuncFlowListener struct {
	accept func(FlowInstance, FlowInstance, FlowService, net.Conn)
	dial   func(context.Context) (net.Conn, error)
}

// DialContext implements FlowListener.
func (f FuncFlowListener) DialContext(ctx context.Context, target FlowInstance) (net.Conn, error) {
	return f.dial(ctx)
}

// AcceptConn implements FlowListener.
func (f FuncFlowListener) AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
	f.accept(source, target, service, conn)
}

var (
	_ FlowListener = &FuncFlowListener{}
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

func ParseTag(tag string, replace ReplaceFunc) (string, error) {
	tagParts := strings.Split(tag, "/")
	if len(tagParts) == 2 {
		if strings.HasPrefix(tagParts[1], "{") {
			if !strings.HasSuffix(tagParts[1], "}") {
				return "", fmt.Errorf("invalid tag: %s", tagParts[1])
			}
			if replace == nil {
				return "", fmt.Errorf("replace function required for dynamic instance")
			}
			tag := tagParts[1][1 : len(tagParts[1])-1]
			replaceStr, err := replace(tag)
			if err != nil {
				return "", err
			}
			tagParts[1] = replaceStr
		}

		return fmt.Sprintf("%s/%s", tagParts[0], tagParts[1]), nil
	} else {
		return "", fmt.Errorf("invalid tag: %s", tag)
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

type flowRouterHandler struct {
	router   *FlowRouter
	instance FlowInstance
}

// String implements NetHandler.
func (h *flowRouterHandler) String() string {
	return h.Hostname()
}

// IpAddress implements NetHandler.
func (h *flowRouterHandler) IpAddress() net.IP {
	return h.instance.InstanceAddress()
}

// String implements NetHandler.
func (h *flowRouterHandler) Hostname() string {
	return h.instance.Hostname()
}

// HandleConn implements NetHandler.
func (f *flowRouterHandler) HandleConn(network string, ip net.IP, port uint16, conn net.Conn) {
	slog.Debug("handling connection", "source", f.instance.Hostname(), "ip", ip, "port", port)

	// find the target by IP
	for _, inst := range f.router.instances {
		target := inst.instance

		if target.InstanceAddress().Equal(ip) {
			// We found the target, now find the service.
			for _, service := range target.Services() {
				if service.Port() == int(port) {
					slog.Debug("found target", "source", f.instance.Hostname(), "target", target.Hostname(), "service", service.Name())
					// We now know instance is trying to connect to target:service.
					if f.router.handleConnection(f.instance, target, service, conn) {
						return
					}
				}
			}
		}
	}

	// slog.Info("no matching target", "source", instance.InstanceId(), "ip", ip, "port", port)

	// If we reach here, we couldn't find the target.
	// TODO(joshua): Handle a default route.
	slog.Warn("no matching target", "source", f.instance.Hostname(), "ip", ip, "port", port)
	conn.Close()
}

var (
	_ NetHandler = &flowRouterHandler{}
)

type FlowRouter struct {
	instances map[string]*flowRouterHandler
}

func (r *FlowRouter) handleConnection(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) bool {
	// Iterate though each flow.
	for _, flow := range source.Flows() {
		// Check if the source tags match.
		if !source.Tags().ContainsAny(source.Tags()) {
			slog.Debug("rejected source", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name())
			continue
		}

		// Check if the target tags match.
		if flow.Instance == "*" {
			if !target.Tags().ContainsMatchingPrefix(fmt.Sprintf("%s/", flow.Tag)) {
				slog.Debug("rejected target partial", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
				continue
			}
		} else if !target.Tags().Contains(fmt.Sprintf("%s/%s", flow.Tag, flow.Instance)) {
			slog.Debug("rejected target", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
			continue
		}

		// Check if the service tags match.
		if !service.Tags().Contains(flow.Service) {
			slog.Debug("rejected service", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name())
			continue
		}

		// We have a match, accept the connection.
		service.AcceptConn(source, target, service, conn)
		return true
	}
	slog.Debug("no matching flow", "source", source.Hostname(), "target", target.Hostname(), "service", service.Name())
	return false
}

func (r *FlowRouter) dialContext(ctx context.Context, source FlowInstance, target FlowInstance, service FlowService, network, address string) (net.Conn, error) {
	if source == nil {
		// If source is nil, we are dialing from the router itself.
		return service.DialContext(ctx, target)
	}

	// Otherwise we are dialing from an instance so validate it's a valid flow.
	for _, flow := range source.Flows() {
		// Check if the source tags match.
		if !source.Tags().ContainsAny(source.Tags()) {
			slog.Debug("rejected source", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name)
			continue
		}

		// Check if the target tags match.
		if flow.Instance == "*" {
			if !target.Tags().ContainsMatchingPrefix(fmt.Sprintf("%s/", flow.Tag)) {
				slog.Debug("rejected target partial", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
				continue
			}
		} else if !target.Tags().Contains(fmt.Sprintf("%s/%s", flow.Tag, flow.Instance)) {
			slog.Debug("rejected target", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "targetTags", target.Tags())
			continue
		}

		// Check if the service tags match.
		if !service.Tags().Contains(flow.Service) {
			slog.Debug("rejected service", "flow", flow, "source", source.Hostname(), "target", target.Hostname(), "service", service.Name)
			continue
		}

		// We have a match, dial the connection.
		return service.DialContext(ctx, target)
	}

	return nil, fmt.Errorf("no matching flow: %s", address)
}

func (r *FlowRouter) DialContext(ctx context.Context, source FlowInstance, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	slog.Debug("dialing", "source", source, "network", network, "address", address)

	// Parse the address.
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	// Find the target instance.
	for _, inst := range r.instances {
		target := inst.instance

		slog.Debug("checking target", "target", target.Hostname(), "instanceAddress", target.InstanceAddress().String(), "host", host)

		if target.Hostname() == host {
			// We found the target, now find the service.
			for _, service := range target.Services() {
				if strconv.Itoa(service.Port()) == port || service.Name() == port {
					// We now know instance is trying to connect to target:service.
					return r.dialContext(ctx, source, target, service, network, address)
				}
			}
		}

		if target.InstanceAddress().String() == host {
			// We found the target, now find the service.
			for _, service := range target.Services() {
				if strconv.Itoa(service.Port()) == port || service.Name() == port {
					// We now know instance is trying to connect to target:service.
					return r.dialContext(ctx, source, target, service, network, address)
				}
			}
		}
	}

	return nil, fmt.Errorf("no matching target: %s -> %s", source, address)
}

func (r *FlowRouter) AddInstance(instance FlowInstance) (NetHandler, error) {
	if _, ok := r.instances[instance.Hostname()]; ok {
		return nil, fmt.Errorf("instance already exists: %s", instance.Hostname())
	}

	handler := &flowRouterHandler{
		router:   r,
		instance: instance,
	}

	r.instances[instance.Hostname()] = handler

	return handler, nil
}

func NewFlowRouter() *FlowRouter {
	return &FlowRouter{
		instances: make(map[string]*flowRouterHandler),
	}
}
