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
	defaultTsnetPort     = 22
)

type Policy struct {
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
	Rules          ruleset  `json:"rules,omitempty"`
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
	path    string
	signers []ssh.Signer

	Policies     []Policy     `json:"policies,omitempty"`
	Tsnet        Tsnet        `json:"tsnet"`
	HostKeyPaths HostKeyPaths `json:"host_key_paths"`
}

func ReadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := Config{
		path: path,

		Tsnet: Tsnet{
			Hostname: defaultTsnetHostname,
			Port:     defaultTsnetPort,
		},
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
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
