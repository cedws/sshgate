package sshgate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTsnetHostname = "sshgate"
	defaultTsnetPort     = 36867
)

type Identity struct {
	AuthorizedKeys []string  `json:"authorized_keys,omitempty"`
	Rules          []RawRule `json:"rules,omitempty"`
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
	Identities   []Identity   `json:"identities,omitempty"`
	Tsnet        Tsnet        `json:"tsnet"`
	HostKeyPaths HostKeyPaths `json:"host_key_paths"`

	signers          []ssh.Signer
	identityRulesets map[string][]*Ruleset
}

func (c Config) Validate() error {
	for _, identities := range c.Identities {
		for _, key := range identities.AuthorizedKeys {
			_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
			if err != nil {
				return fmt.Errorf("failed to validate config: %w", err)
			}
		}

		for _, rule := range identities.Rules {
			for _, host := range rule.Hosts {
				if _, err := tryParseHostSpec(host); err != nil {
					return err
				}
			}
		}
	}

	return nil
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
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}
	if err := config.Validate(); err != nil {
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

	config.identityRulesets = parseIdentities(config.Identities)

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

func parseIdentities(identities []Identity) map[string][]*Ruleset {
	rulesByFingerprints := make(map[string][]*Ruleset)

	for _, identities := range identities {
		ruleset := parseRuleset(identities.Rules)

		for _, rawPubkey := range identities.AuthorizedKeys {
			authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawPubkey))
			if err != nil {
				// already validated
				panic(err)
			}

			fingerprint := ssh.FingerprintSHA256(authorizedKey)
			rulesByFingerprints[fingerprint] = append(rulesByFingerprints[fingerprint], &ruleset)
		}
	}

	return rulesByFingerprints
}

func parseRuleset(rawRules []RawRule) Ruleset {
	var ruleset Ruleset

	for _, rawRule := range rawRules {
		var hostSpecs []hostSpec

		for _, host := range rawRule.Hosts {
			hostSpec, err := tryParseHostSpec(host)
			if err != nil {
				// already validated
				panic(err)
			}
			hostSpecs = append(hostSpecs, hostSpec)
		}

		ruleset = append(ruleset, Rule{
			Hosts: hostSpecs,
			Ports: rawRule.Ports,
		})
	}

	return ruleset
}
