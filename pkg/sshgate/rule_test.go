package sshgate

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func makeRule(hosts []string, ports []int) Rule {
	var hostSpecs []hostSpec
	for _, h := range hosts {
		hostSpecs = append(hostSpecs, mustParseHostSpec(h))
	}
	return Rule{
		Hosts: hostSpecs,
		Ports: ports,
	}
}

func TestRulesetTableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rules    Ruleset
		destHost string
		destPort int
		want     bool
	}{
		{
			name:     "CIDR matches same subnet and port",
			rules:    Ruleset{makeRule([]string{"192.168.0.0/24"}, []int{443})},
			destHost: "192.168.0.1",
			destPort: 443,
			want:     true,
		},
		{
			name:     "CIDR does not match different subnet",
			rules:    Ruleset{makeRule([]string{"192.168.0.0/24"}, []int{443})},
			destHost: "10.0.0.1",
			destPort: 443,
			want:     false,
		},
		{
			name:     "IP exact match with default port allowed",
			rules:    Ruleset{makeRule([]string{"192.168.0.1"}, nil)}, // nil ports => defaultAllowPort only
			destHost: "192.168.0.1",
			destPort: defaultAllowPort,
			want:     true,
		},
		{
			name:     "IP exact match but wrong port",
			rules:    Ruleset{makeRule([]string{"192.168.0.1"}, nil)},
			destHost: "192.168.0.1",
			destPort: 443,
			want:     false,
		},
		{
			name:     "Hostname match is case-insensitive",
			rules:    Ruleset{makeRule([]string{"Example.COM"}, []int{443})},
			destHost: "example.com",
			destPort: 443,
			want:     true,
		},
		{
			name:     "Hostname does not match different name",
			rules:    Ruleset{makeRule([]string{"example.com"}, []int{443})},
			destHost: "example.org",
			destPort: 443,
			want:     false,
		},
		{
			name: "Multiple rules: second rule matches",
			rules: Ruleset{
				makeRule([]string{"google.com"}, []int{443}),
				makeRule([]string{"10.1.1.0/24"}, []int{80}),
			},
			destHost: "10.1.1.5",
			destPort: 80,
			want:     true,
		},
		{
			name: "Multiple rules: none match",
			rules: Ruleset{
				makeRule([]string{"google.com"}, []int{443}),
				makeRule([]string{"10.1.1.0/24"}, []int{80}),
			},
			destHost: "10.1.1.5",
			destPort: 22,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := mustParseHostSpec(tc.destHost)
			got := tc.rules.Matches(h, tc.destPort)
			assert.Equal(t, tc.want, got)
		})
	}
}
