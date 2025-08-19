package sshgate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type Identity struct {
	AuthorizedKeys []string  `json:"authorized_keys,omitempty"`
	Rules          []RawRule `json:"rules,omitempty"`
}

type RawRule struct {
	Hosts []string `json:"hosts,omitempty"`
	Ports []int    `json:"ports,omitempty"`
}

type Config struct {
	Identities []Identity `json:"identities,omitempty"`

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

func Open(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	config.signers, err = parseHostKeys()
	if err != nil {
		return nil, fmt.Errorf("invalid host keys: %w", err)
	}

	config.identityRulesets = parseIdentities(config.Identities)

	return &config, nil
}

func parseHostKeys() ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for _, envVar := range []string{
		"SSHPROXY_HOST_KEY_PATH_RSA",
		"SSHPROXY_HOST_KEY_PATH_ED25519",
		"SSHPROXY_HOST_KEY_PATH_ECDSA",
	} {
		keyPath := os.Getenv(envVar)
		if keyPath == "" {
			continue
		}

		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read host key %s: %w", envVar, err)
		}

		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key %s: %w", envVar, err)
		}

		signers = append(signers, signer)
	}

	return signers, nil
}

func generateSigner() (ssh.Signer, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	signer, err := ssh.NewSignerFromSigner(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
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
