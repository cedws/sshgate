package sshgate

import "sync"

type principalType string

const (
	principalTypeFingerprint   = "fingerprint"
	principalTypeTailscaleNode = "tailscale_node"
)

func newPolicyEngine() *policyEngine {
	return &policyEngine{
		fingerprints:   make(map[string]ruleset),
		tailscaleNodes: make(map[string]ruleset),
	}
}

type policyEngine struct {
	sync.RWMutex
	fingerprints   map[string]ruleset
	tailscaleNodes map[string]ruleset
}

func (p *policyEngine) AddPolicy(principalType principalType, principal string, rules ruleset) {
	p.Lock()
	defer p.Unlock()

	switch principalType {
	case principalTypeFingerprint:
		p.fingerprints[principal] = append(p.fingerprints[principal], rules...)
	case principalTypeTailscaleNode:
		p.tailscaleNodes[principal] = append(p.tailscaleNodes[principal], rules...)
	}
}

func (p *policyEngine) RemovePolicy(principalType principalType, principal string) {
	p.Lock()
	defer p.Unlock()

	switch principalType {
	case principalTypeFingerprint:
		delete(p.fingerprints, principal)
	case principalTypeTailscaleNode:
		delete(p.tailscaleNodes, principal)
	}
}

func (p *policyEngine) Principal(principalType principalType, principal string) (ruleset, bool) {
	p.RLock()
	defer p.RUnlock()

	var rules ruleset
	var ok bool

	switch principalType {
	case principalTypeFingerprint:
		rules, ok = p.fingerprints[principal]
	case principalTypeTailscaleNode:
		rules, ok = p.tailscaleNodes[principal]
	}

	return rules, ok
}

func (p *policyEngine) Allowed(fingerprint, nodeID string, host hostSpec, port int) bool {
	p.RLock()
	defer p.RUnlock()

	if nodeID != "" {
		if rules, ok := p.tailscaleNodes[nodeID]; ok && rules.Matches(host, port) {
			return true
		}
	}

	if rules, ok := p.fingerprints[fingerprint]; ok && rules.Matches(host, port) {
		return true
	}

	return false
}
