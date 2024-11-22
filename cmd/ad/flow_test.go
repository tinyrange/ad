package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestParseFlow(t *testing.T) {
	// Test a series of options including static and dynamic flows.
	tests := []struct {
		flow     string
		replace  ReplaceFunc
		expected ParsedFlow
		err      bool
	}{
		{
			flow: "tag/*:service",
			expected: ParsedFlow{
				Tag:      "tag",
				Instance: "*",
				Service:  "service",
			},
		},
		{
			flow: "tag/{in}:service",
			replace: func(tag string) (string, error) {
				if tag != "in" {
					return "", fmt.Errorf("unexpected tag: %s", tag)
				}

				return "instance", nil
			},
			expected: ParsedFlow{
				Tag:      "tag",
				Instance: "instance",
				Service:  "service",
			},
		},
		{
			flow: "tag/{in:service",
			replace: func(tag string) (string, error) {
				if tag != "in" {
					return "", fmt.Errorf("unexpected tag: %s", tag)
				}

				return "instance", nil
			},
			err: true,
		},
		{
			flow: "tag/*:service",
			expected: ParsedFlow{
				Tag:      "tag",
				Instance: "*",
				Service:  "service",
			},
		},
		{
			flow: "tag:service:extra",
			err:  true,
		},
		{
			flow: "tag/instance/service",
			err:  true,
		},
	}

	for i, test := range tests {
		flow, err := ParseFlow(test.flow, test.replace)
		if err != nil && !test.err {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}

		if err == nil && test.err {
			t.Errorf("Test %d: expected error", i)
			continue
		}

		if flow.Tag != test.expected.Tag {
			t.Errorf("Test %d: tag mismatch: %s != %s", i, flow.Tag, test.expected.Tag)
		}

		if flow.Instance != test.expected.Instance {
			t.Errorf("Test %d: instance mismatch: %s != %s", i, flow.Instance, test.expected.Instance)
		}

		if flow.Service != test.expected.Service {
			t.Errorf("Test %d: service mismatch: %s != %s", i, flow.Service, test.expected.Service)
		}
	}
}

type testInstance struct {
	flows    []ParsedFlow
	ip       net.IP
	id       string
	services []Service
	tags     TagList
}

// implements Instance.
func (t *testInstance) Flows() []ParsedFlow     { return t.flows }
func (t *testInstance) InstanceAddress() net.IP { return t.ip }
func (t *testInstance) InstanceId() string      { return t.id }
func (t *testInstance) Services() []Service     { return t.services }
func (t *testInstance) Tags() TagList           { return t.tags }

var (
	_ FlowInstance = &testInstance{}
)

type testConn struct {
	t *testing.T
}

// RemoteAddr implements net.Conn.
func (t *testConn) RemoteAddr() net.Addr              { panic("unimplemented") }
func (t *testConn) Close() error                      { t.t.Fatalf("unexpected call to Close"); return nil }
func (t *testConn) LocalAddr() net.Addr               { panic("unimplemented") }
func (t *testConn) Read(b []byte) (n int, err error)  { panic("unimplemented") }
func (*testConn) SetDeadline(t time.Time) error       { panic("unimplemented") }
func (*testConn) SetReadDeadline(t time.Time) error   { panic("unimplemented") }
func (*testConn) SetWriteDeadline(t time.Time) error  { panic("unimplemented") }
func (t *testConn) Write(b []byte) (n int, err error) { panic("unimplemented") }

var (
	_ net.Conn = &testConn{}
)

func TestFlowRouter(t *testing.T) {
	router := NewFlowRouter()

	success := false

	// Create a test instance.
	instance1 := &testInstance{
		flows: []ParsedFlow{
			{
				Tag:      "tag",
				Instance: "*",
				Service:  "service",
			},
		},
		ip: net.IP{10, 40, 0, 1},
		id: "instance1",
		services: []Service{
			{
				Name: "service",
				Port: 1234,
				Tags: TagList{"service"},
				Listener: FuncFlowListener(func(fi FlowInstance, s Service, c net.Conn) {
					success = true
				}),
			},
		},
		tags: TagList{"tag/instance"},
	}

	// Register the instance.
	instance2 := &testInstance{
		flows: []ParsedFlow{
			{
				Tag:      "tag",
				Instance: "*",
				Service:  "service",
			},
		},
		ip: net.IP{10, 40, 0, 2},
		id: "instance2",
		services: []Service{
			{
				Name: "service",
				Port: 1234,
				Tags: TagList{"service"},
				Listener: FuncFlowListener(func(fi FlowInstance, s Service, c net.Conn) {
					t.Fatalf("unexpected call to listener")
				}),
			},
		},
		tags: TagList{"tag/instance"},
	}

	netHandler1, err := router.AddInstance(instance1)
	if err != nil {
		t.Fatalf("failed to add instance 1: %v", err)
	}

	_ = netHandler1

	netHandler2, err := router.AddInstance(instance2)
	if err != nil {
		t.Fatalf("failed to add instance 2: %v", err)
	}

	// Create a test connection.
	conn := &testConn{t: t}

	// Test the connection.
	netHandler2.HandleConn("tcp", net.IPv4(10, 40, 0, 1), 1234, conn)

	if !success {
		t.Fatalf("failed to handle connection")
	}
}
