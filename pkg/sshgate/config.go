package sshgate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTsnetHostname = "sshgate"
	defaultTsnetPort     = 22
)

type Policy struct {
	AuthorizedKeys      []string  `json:"authorized_keys,omitempty"`
	TailscalePrincipals []string  `json:"tailscale_principals,omitempty"`
	Rules               []RawRule `json:"rules,omitempty"`
}

type RawRule struct {
	Hosts []string `json:"hosts,omitempty"`
	Ports []int    `json:"ports,omitempty"`
}

type HostKeyPaths struct {
	ECDSA   string `json:"ecdsa,omitempty"`
	ED25519 string `json:"ed25519,omitempty"`
	RSA     string `json:"rsa,omitempty"`
}

type Tsnet struct {
	Enabled  bool   `json:"enabled"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

type Config struct {
	Policies     []Policy     `json:"policies,omitempty"`
	Tsnet        Tsnet        `json:"tsnet"`
	HostKeyPaths HostKeyPaths `json:"host_key_paths"`

	path           string
	signers        []ssh.Signer
	parsedPolicies parsedPolicies
}

type parsedPolicies []parsedPolicy

func (p parsedPolicies) MatchingPolicies(fingerprint, tailscalePrincipal string) ([]parsedPolicy, bool) {
	var matching []parsedPolicy
	var found bool

	for _, policy := range p {
		if fingerprint != "" && policy.AllowsFingerprint(fingerprint) {
			found = true
			matching = append(matching, policy)
		}
		if tailscalePrincipal != "" && policy.AllowsTailscalePrincipal(tailscalePrincipal) {
			found = true
			matching = append(matching, policy)
		}
	}

	return matching, found
}

type parsedPolicy struct {
	Fingerprints        []string
	TailscalePrincipals []string
	Ruleset             ruleset
}

func (p parsedPolicy) AllowsFingerprint(fingerprint string) bool {
	return slices.Contains(p.Fingerprints, fingerprint)
}

func (p parsedPolicy) AllowsTailscalePrincipal(principal string) bool {
	return slices.Contains(p.TailscalePrincipals, principal)
}

func ReadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := Config{
		Tsnet: Tsnet{
			Hostname: defaultTsnetHostname,
			Port:     defaultTsnetPort,
		},

		path: path,
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	config.parsedPolicies, err = parsePolicies(config.Policies)
	if err != nil {
		return nil, err
	}

	config.signers, err = parseHostKeys(config.HostKeyPaths)
	if err != nil {
		return nil, fmt.Errorf("invalid host keys: %w", err)
	}

	if len(config.signers) == 0 {
		slog.Warn("no host keys provided in config, generating ephemeral ed25519 host key")

		signer, err := generateSigner()
		if err != nil {
			return nil, err
		}

		config.signers = append(config.signers, signer)
	}

	return &config, nil
}

func parseHostKeys(hostKeyPaths HostKeyPaths) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for keyType, keyPath := range map[string]string{
		"ssh-ecdsa":   hostKeyPaths.ECDSA,
		"ssh-ed25519": hostKeyPaths.ED25519,
		"ssh-rsa":     hostKeyPaths.RSA,
	} {
		if keyPath == "" {
			continue
		}

		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read host key %s: %w", keyPath, err)
		}

		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key %s: %w", keyPath, err)
		}

		// Don't allow key of unexpected type to be smuggled in
		if signer.PublicKey().Type() != keyType {
			return nil, fmt.Errorf("expected key of type %s but got %s", keyType, signer.PublicKey().Type())
		}

		signers = append(signers, signer)
	}

	return signers, nil
}

func parsePolicies(policies []Policy) (parsedPolicies, error) {
	var parsed parsedPolicies

	for _, policy := range policies {
		parsedPolicy := parsedPolicy{
			TailscalePrincipals: policy.TailscalePrincipals,
		}

		for _, authorizedKey := range policy.AuthorizedKeys {
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
			if err != nil {
				return parsed, err
			}
			parsedPolicy.Fingerprints = append(parsedPolicy.Fingerprints, ssh.FingerprintSHA256(pubKey))
		}

		rule, err := parseRuleset(policy.Rules)
		if err != nil {
			return parsed, err
		}
		parsedPolicy.Ruleset = append(parsedPolicy.Ruleset, rule...)

		parsed = append(parsed, parsedPolicy)
	}

	return parsed, nil
}

func parseRuleset(rawRules []RawRule) (ruleset, error) {
	var ruleset ruleset

	for _, rawRule := range rawRules {
		var hostSpecs []hostSpec

		for _, host := range rawRule.Hosts {
			hostSpec, err := tryParseHostSpec(host)
			if err != nil {
				return ruleset, err
			}
			hostSpecs = append(hostSpecs, hostSpec)
		}

		ruleset = append(ruleset, rule{
			Hosts: hostSpecs,
			Ports: rawRule.Ports,
		})
	}

	return ruleset, nil
}
