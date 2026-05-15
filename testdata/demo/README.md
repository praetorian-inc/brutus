# Brutus Demo Environment

This directory contains a demo environment for showcasing the full Brutus pipeline:
**naabu** (port scan) -> **nerva** (service fingerprint) -> **brutus** (credential test)

## Quick Start

```bash
# One-liner: spin up environment and run full demo
make demo

# Or step by step:
make demo-up        # Start vulnerable containers
make demo-ssh-key   # Test just SSH with private key
make demo-down      # Tear down when done
```

## Vulnerable Services

| Service | Port | Credentials |
|---------|------|-------------|
| SSH | 2222 | `vagrant` / `vagrant` OR Vagrant insecure key (auto-detected by `--badkeys`) |
| MySQL | 3306 | `root` / `rootpass` |
| Redis | 6379 | password: `redispass` |
| FTP | 21 | `ftpuser` / `ftppass` |

## SSH Private Key Demo

The `vulnerable_key` is the well-known **Vagrant insecure private key** - included in Brutus's
embedded badkeys collection. This simulates finding default/hardcoded keys in:
- Vagrant base boxes
- Development environments
- CI/CD pipelines
- Appliances with known default keys

```bash
# Test SSH authentication with badkeys (auto-detects the Vagrant key)
brutus badkeys --target 127.0.0.1:2222

# Or explicitly with the key file
brutus badkeys --target 127.0.0.1:2222 -u vagrant -k testdata/demo/vulnerable_key
```

## Full Pipeline Demo

```bash
# Port scan -> Service fingerprint -> Credential test
naabu -host 127.0.0.1 -p 21,2222,3306,6379 -silent | \
  nerva --json | \
  brutus creds -u root,vagrant,ftpuser -p "rootpass,vagrant,ftppass,redispass"
```

## Files

- `docker-compose.yml` - Demo service definitions
- `Dockerfile.ssh` - Vulnerable SSH server with authorized key
- `vulnerable_key` - Private key (intentionally "leaked" for demo)
- `vulnerable_key.pub` - Corresponding public key

## Warning

This environment is **intentionally insecure** for demonstration purposes.
Do not expose these services to untrusted networks.
