# sshgate

sshgate is a proxy SSH server/firewall built to run at a network boundary. It takes a JSON config file that defines the hosts and ports that SSH identities can reach.

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

The example config contains a rule allowing the client to jump to `github:22`. If you try some other host or port, you'll see something like this:

```
$ ssh -J localhost:2222 bitbucket.org
channel 0: open failed: administratively prohibited: remote connection denied
stdio forwarding failed
Connection closed by UNKNOWN port 65535
```

sshgate doesn't care about the username used for the jump hop. It doesn't care about the usernames in subsequent hops either; that information is opaque, it simply forwards the traffic to the client.

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
