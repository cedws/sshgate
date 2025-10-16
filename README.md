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

Copy the example `config.json` and add your own SSH public key to the `authorized_keys` array, then start it up:

```
sshgate --config config.json
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

If no ports are specified in a rule, port 22 is allowed by default.

### Identity

Since we didn't pass any SSH host keys to sshgate earlier, it generated an ephemeral ED25519 host key on startup. For the server to have a persistent identity, generate an SSH keypair and set `host_key_paths` in the config file accordingly. You may set an ED25519, ECDSA, and RSA host key.

For example, to set the server's ED25519 identity:

```
ssh-keygen -t ed25519 -f sshgate
```

Add to the config:

```json
{
  "host_key_paths": {
    "ed25519": "./sshgate"
  }
}
```

## Tailscale Integration

sshgate can join your Tailscale network (tailnet) directly like an appliance. You can configure the tailnet hostname and port in the JSON config:

```json
{
  "tsnet": {
    "enabled": true,
    "hostname": "sshgate",
    "port": 22
  }
}
```

To have sshgate join your tailnet, create a `Linux server` device in the Tailscale console and copy the auth key. Export the value as `TS_AUTH_KEY` as an environment variable and start sshgate.

```bash
export TS_AUTH_KEY=tskey-auth-xxx sshgate --config config.json
```

You should see sshgate join the tailnet with the configured hostname and be able to SSH to it using any authorized key.

Using Tailscale's [tsnet](https://tailscale.com/kb/1244/tsnet) library, sshgate can authenticate clients by their Tailscale identity, eliminating the need for public key management in the config, while [app capabilities](https://tailscale.com/kb/1537/grants-app-capabilities) enable SSH rules to be directly configured inside the tailnet access controls.

Use this tailnet policy file as a starting point. You'll need to attach the `sshgate` tag to the `sshgate` machine on your network after applying the policy.

```json
{
  "tagOwners": {
    "tag:sshgate": ["autogroup:admin"]
  },

  "grants": [
    {
      "src": ["*"],
      "dst": ["tag:sshgate"],
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

Ensure that the JSON under `"github.com/cedws/sshgate"` isn't malformed or clients won't be able to connect.
