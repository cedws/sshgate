# sshgate

A forwarding-only SSH server with policy-based connection control for restricted jump hosts and bastions.

I made this for my experimental [devenv](https://github.com/cedws/devenv) project in which I'm building a locked down development environment with restricted outbound traffic. sshgate facilitates my goal of only allowing outbound SSH traffic to `github.com:22`.

## Installation

### Brew

```bash
brew install cedws/tap/sshgate
```

### Scoop

```powershell
scoop bucket add cedws https://github.com/cedws/scoop-bucket.git
scoop install sshgate
```

### Docker

```bash
docker pull ghcr.io/cedws/sshgate:latest
```

## Usage

sshgate is an SSH server that only handles `direct-tcpip` channels, meaning it will only opaquely forward traffic from a remote host if there's a rule for the connected identity allowing it. It doesn't grant a PTY.

Configuration files may use JSON or JSONC/HuJSON syntax, including comments and trailing commas. Three example configurations are provided:

* [`static-authorized-key.jsonc`](examples/config/static-authorized-key.jsonc) listens on the command-line address and authenticates clients with an SSH public key.
* [`tailscale-service.jsonc`](examples/config/tailscale-service.jsonc) publishes sshgate as a Tailscale Service and is the recommended Tailscale configuration.
* [`tailscale-node.jsonc`](examples/config/tailscale-node.jsonc) runs sshgate as an ordinary tsnet node.

For a local setup, copy the static-key example, replace its `authorized_keys` entry with your public key, generate the configured host key, and start sshgate:

```fish
cp examples/config/static-authorized-key.jsonc config.jsonc
ssh-keygen -t ed25519 -f sshgate-host-key
sshgate --config config.jsonc
```

You can now use it as a jump host to reach a remote host:

```
ssh -J localhost:2222 git@github.com
```

The example config contains a rule allowing the client to jump to `github.com:22`. If you try some other host or port, you'll see something like this:

```
$ ssh -J localhost:2222 bitbucket.org
channel 0: open failed: administratively prohibited: remote connection denied
stdio forwarding failed
Connection closed by UNKNOWN port 65535
```

sshgate doesn't care about the username used for the jump hop. It doesn't care about the usernames in subsequent hops either; that information is opaque, it simply forwards the traffic to the client.

### Rules

The default policy is to block all connections. The `rules` array describes what hosts and ports to allow forwarding to. If you just want to use sshgate for a bastion without firewalling you can run it with `--ruleless`, which disables firewall rules.

A host can be any of the following:

* Hostname (e.g. `github.com`, wildcards not supported)
* IP address (e.g. `1.1.1.1`)
* CIDR range (e.g. `192.168.1.1/24`)

If no ports are specified in a rule, port 22 is allowed by default.

### Host identity

The server host key identifies sshgate to connecting SSH clients. Generate a persistent key and configure it through `host_key_paths`; otherwise, sshgate generates an ephemeral ED25519 host key each time it starts. ED25519, ECDSA, and RSA host keys are supported.

For example:

```fish
ssh-keygen -t ed25519 -f sshgate-host-key
```

Add to the config:

```jsonc
{
  "host_key_paths": {
    "ed25519": "./sshgate-host-key",
  },
}
```

## Tailscale Integration

Using Tailscale's [tsnet](https://tailscale.com/kb/1244/tsnet) library, sshgate can authenticate clients by their Tailscale identity. [App capabilities](https://tailscale.com/kb/1537/grants-app-capabilities) then provide forwarding rules directly from the tailnet access controls, eliminating the need to manage client public keys in the sshgate configuration.

### Tailscale Service

The recommended approach is the [`tailscale-service.jsonc`](examples/config/tailscale-service.jsonc) example, which publishes sshgate as [`svc:sshgate`](https://tailscale.com/docs/features/tailscale-services). Define the Service in the Tailscale admin console before starting sshgate, then approve its advertised host or configure a service auto-approver.

The tsnet node hostname must be different from the Service name. The node is the host running sshgate, while the Service has its own MagicDNS name and TailVIP. Multiple approved nodes can advertise the same Service, allowing Tailscale to provide failover, traffic steering, and draining without changing the address used by clients.

```fish
set -x TS_AUTH_KEY tskey-auth-xxx
sshgate --config examples/config/tailscale-service.jsonc
```

### Ordinary tsnet node

The [`tailscale-node.jsonc`](examples/config/tailscale-node.jsonc) example is the other approach. It gives sshgate its own Tailscale node identity and MagicDNS hostname and is simpler for a single persistent instance.

Create a tagged auth key in the Tailscale console, set `TS_AUTH_KEY`, and start sshgate:

```fish
set -x TS_AUTH_KEY tskey-auth-xxx
sshgate --config examples/config/tailscale-node.jsonc
```

Preserve the tsnet state directory to retain the same node identity between restarts.

### Tailnet grants

Use this tailnet policy as a starting point for the Service example. For an ordinary tsnet node, change the grant destination from `svc:sshgate` to `tag:sshgate`.

```json
{
  "tagOwners": {
    "tag:sshgate": ["autogroup:admin"]
  },

  "grants": [
    {
      "src": ["*"],
      "dst": ["svc:sshgate"],
      "ip": ["22"],
      "app": {
        "github.com/cedws/sshgate": [
          {
            "hosts": ["github.com"],
            "ports": [22]
          }
        ]
      }
    }
  ]
}
```

The `ip` field controls access to sshgate itself. The objects under `github.com/cedws/sshgate` control the destinations that an authenticated client may reach through sshgate. Clients cannot connect when no matching app capability supplies an allowed destination.
