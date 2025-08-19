package sshgate

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

const defaultAllowPort = 22

type Ruleset []Rule

type Rule struct {
	Hosts []hostSpec
	Ports []int
}

func (r Rule) Matches(host hostSpec, port int) bool {
	if len(r.Ports) == 0 {
		if port != defaultAllowPort {
			return false
		}
	} else {
		if !slices.Contains(r.Ports, port) {
			return false
		}
	}

	return slices.ContainsFunc(r.Hosts, func(host2 hostSpec) bool {
		return host.Matches(host2)
	})
}

func (r Ruleset) Matches(host hostSpec, port int) bool {
	for _, rule := range r {
		if rule.Matches(host, port) {
			return true
		}
	}

	return false
}

type hostSpec interface {
	Matches(hostSpec) bool
}

type cidrHost struct {
	ip    net.IP
	ipnet *net.IPNet
}

type ipHost struct {
	ip net.IP
}

type nameHost struct {
	name string
}

func (c cidrHost) Matches(host hostSpec) bool {
	switch t := host.(type) {
	case cidrHost:
		return c.ipnet.Contains(t.ip)
	case ipHost:
		return c.ipnet.Contains(t.ip)
	}

	return false
}

func (i ipHost) Matches(host hostSpec) bool {
	switch t := host.(type) {
	case cidrHost:
		return t.ipnet.Contains(i.ip)
	case ipHost:
		return t.ip.Equal(i.ip)
	}

	return false
}

func (n nameHost) Matches(host hostSpec) bool {
	switch h := host.(type) {
	case nameHost:
		return strings.EqualFold(h.name, n.name)
	}

	return false
}

func tryParseHostSpec(host string) (hostSpec, error) {
	if strings.Contains(host, "/") {
		if host, err := tryParseCIDR(host); err == nil {
			// If NO error
			return host, nil
		}
	}

	if strings.ContainsAny(host, ".:") {
		if host, err := tryParseIP(host); err == nil {
			// If NO error
			return host, nil
		}
	}

	if host, err := tryParseName(host); err == nil {
		// If NO error
		return host, nil
	}

	return nil, fmt.Errorf("invalid host rule %s, could not parse as CIDR, IP, or plain hostname", host)
}

func mustParseHostSpec(host string) hostSpec {
	h, err := tryParseHostSpec(host)
	if err != nil {
		panic(err)
	}
	return h
}

func tryParseCIDR(host string) (hostSpec, error) {
	ip, ipnet, err := net.ParseCIDR(host)
	if err != nil {
		return nil, err
	}

	return cidrHost{ip, ipnet}, nil
}

func tryParseIP(host string) (hostSpec, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip address: %s", host)
	}

	return ipHost{ip}, nil
}

func tryParseName(host string) (hostSpec, error) {
	// TODO: validate hostname?
	return nameHost{host}, nil
}
