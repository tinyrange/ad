package main

import (
	"fmt"
	"net"
)

type DeviceConfig struct {
	Config string
	ID     int
}

type WireguardDevice struct {
	Config string
	Name   string
	IP     string
}

type Device struct {
	game  *AttackDefenseGame
	wg    WireguardInstance
	name  string
	team  string
	id    int
	ip    string
	flows []ParsedFlow
}

// implements FlowInstance.
func (d *Device) Flows() []ParsedFlow     { return d.flows }
func (d *Device) Hostname() string        { return "device_" + d.name }
func (d *Device) InstanceAddress() net.IP { return net.ParseIP(d.ip) }
func (d *Device) Services() []FlowService { return []FlowService{} }
func (d *Device) Tags() TagList           { return d.game.Config.Device.Tags }

func (d *Device) ParseFlows() error {
	flows, err := d.game.Config.Device.Flows.Parse(func(s string) (string, error) {
		if s == "team" {
			return d.team, nil
		} else {
			return "", fmt.Errorf("invalid flow variable: %s", s)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to parse flows for device (%s): %w", d.name, err)
	}

	d.flows = flows

	return nil
}

var (
	_ FlowInstance = &Device{}
)
