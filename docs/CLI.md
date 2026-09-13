<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# brutus CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:1d4cc140290018ebec0060e5db81bb43f05ff38068f9deacee1592ed70cadfa2`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`brutus`](#brutus) | *(none)* | Brutus - Et tu, Brute? |
| [`brutus badkeys`](#brutus-badkeys) | `keys`, `ssh-keys`, `badkey` | Test known weak/compromised SSH keys against targets |
| [`brutus creds`](#brutus-creds) | `services`, `defaults`, `credentials` | Test default credentials on non-HTTP services (SSH, databases, SMB, etc.) |
| [`brutus enum`](#brutus-enum) | *(none)* | Enumerate accounts against account-existence oracles or Active Directory |
| [`brutus enum active`](#brutus-enum-active) | *(none)* | Active account-existence enumeration against live oracles & directories |
| [`brutus enum active custom`](#brutus-enum-active-custom) | *(none)* | Run a declaratively-described enumeration oracle from a spec file |
| [`brutus enum active github`](#brutus-enum-active-github) | *(none)* | Enumerate GitHub accounts by email (existence + username reveal) |
| [`brutus enum active github map`](#brutus-enum-active-github-map) | *(none)* | Correlate known emails to GitHub usernames (reveal-only, skips existence checks) |
| [`brutus enum active google`](#brutus-enum-active-google) | *(none)* | Enumerate Google Workspace accounts (existence + SSO/IdP) |
| [`brutus enum active gravatar`](#brutus-enum-active-gravatar) | *(none)* | Enumerate accounts with a registered Gravatar (by email) |
| [`brutus enum active kerberos`](#brutus-enum-active-kerberos) | *(none)* | Enumerate Active Directory users via Kerberos AS-REQ |
| [`brutus enum active microsoft365`](#brutus-enum-active-microsoft365) | *(none)* | Enumerate Microsoft 365 accounts (existence + federation/tenant) |
| [`brutus enum active oracles`](#brutus-enum-active-oracles) | *(none)* | Enumerate which account-existence oracles work for an organization |
| [`brutus enum active oracles discover`](#brutus-enum-active-oracles-discover) | *(none)* | Discover working oracles by testing a known-valid email |
| [`brutus enum active teams`](#brutus-enum-active-teams) | *(none)* | Microsoft Teams: device-code auth, user enumeration, and tenant posture audit |
| [`brutus enum active teams audit`](#brutus-enum-active-teams-audit) | *(none)* | Audit a Microsoft Teams tenant's external posture into graded findings |
| [`brutus enum active teams auth`](#brutus-enum-active-teams-auth) | *(none)* | Obtain Microsoft access token and refresh token via device code flow |
| [`brutus enum active teams users`](#brutus-enum-active-teams-users) | *(none)* | Enumerate corporate Microsoft Teams users by email address |
| [`brutus enum apollo`](#brutus-enum-apollo) | *(none)* | Discover people for a domain via Apollo.io (free; --enrich reveals emails) (deprecated: use "brutus enum passive apollo" instead) |
| [`brutus enum dehashed`](#brutus-enum-dehashed) | *(none)* | Collect breach-exposed identity data for a domain via DeHashed (deprecated: use "brutus enum passive dehashed" instead) |
| [`brutus enum generate`](#brutus-enum-generate) | *(none)* | Generate email addresses or usernames from embedded name lists |
| [`brutus enum hunter`](#brutus-enum-hunter) | *(none)* | Discover people and emails for a domain via Hunter.io Domain Search (deprecated: use "brutus enum passive hunter" instead) |
| [`brutus enum lusha`](#brutus-enum-lusha) | *(none)* | Enrich a single person identity to emails and phones via Lusha v3 (deprecated: use "brutus enum passive lusha" instead) |
| [`brutus enum passive`](#brutus-enum-passive) | *(none)* | API-key OSINT/HUMINT sources — employee email/contact discovery & enrichment |
| [`brutus enum passive apollo`](#brutus-enum-passive-apollo) | *(none)* | Discover people for a domain via Apollo.io (free; --enrich reveals emails) |
| [`brutus enum passive dehashed`](#brutus-enum-passive-dehashed) | *(none)* | Collect breach-exposed identity data for a domain via DeHashed |
| [`brutus enum passive hunter`](#brutus-enum-passive-hunter) | *(none)* | Discover people and emails for a domain via Hunter.io Domain Search |
| [`brutus enum passive linkedin`](#brutus-enum-passive-linkedin) | *(none)* | Scrape LinkedIn Sales Navigator profiles via PhantomBuster |
| [`brutus enum passive lusha`](#brutus-enum-passive-lusha) | *(none)* | Enrich a single person identity to emails and phones via Lusha v3 |
| [`brutus logon`](#brutus-logon) | *(none)* | Detect Windows logon-screen backdoors (runs both sticky keys and utilman) |
| [`brutus snmp`](#brutus-snmp) | `community` | Test SNMP community strings against targets |
| [`brutus stickykeys`](#brutus-stickykeys) | *(none)* | Detect the Windows sticky-keys (sethc.exe) logon backdoor only |
| [`brutus utilman`](#brutus-utilman) | *(none)* | Detect the Windows utilman (Ease of Access) logon backdoor only |
| [`brutus web`](#brutus-web) | `http`, `panels` | Audit HTTP/web panel credentials (AI-powered or credential list) |

## `brutus`

Brutus - Et tu, Brute?

- Usage: `brutus`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |
| `--version` |  | bool | `false` | Show version information |

## `brutus badkeys`

Test known weak/compromised SSH keys against targets

- Usage: `brutus badkeys`
- Aliases: `keys`, `ssh-keys`, `badkey`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Single target
brutus badkeys --target 192.168.1.10:22

# Targets file (auto-fingerprinted, only SSH services tested)
brutus badkeys --targets-file targets.txt

# Pipeline mode
naabu -host 10.0.0.0/24 -p 22 -silent | nerva --json | brutus badkeys

# Pipe plain targets
echo "192.168.1.10:22" | brutus badkeys

# URI format
echo "ssh://192.168.1.10:22" | brutus badkeys

# Import targets from nmap XML scan (only SSH services tested)
brutus badkeys --nmap-file scan.xml
```

## `brutus creds`

Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)

- Usage: `brutus creds`
- Aliases: `services`, `defaults`, `credentials`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--credentials` | `-c` | string |  | Comma-separated user:pass pairs (e.g., admin:admin,root:toor) |
| `--credentials-file` | `-C` | string |  | Credentials file (user:pass per line) |
| `--key` | `-k` | string |  | SSH private key file |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--max-attempts` |  | int | `0` | Max password attempts per user (0 = unlimited) |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--password-file` | `-P` | string |  | Password file (one per line) |
| `--passwords` | `-p` | string |  | Comma-separated passwords |
| `--protocol` |  | string |  | Protocol to use (auto-detected from nerva) |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |
| `--username-file` | `-U` | string |  | Username file (one per line) |
| `--usernames` | `-u` | string | `root,admin` | Comma-separated usernames |
| `--verify` |  | bool | `false` | Require strict TLS certificate verification |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Single target
brutus creds --target 192.168.1.10:22 --protocol ssh -p "password,Password1"

# Pre-paired user:pass combos (no Cartesian product)
brutus creds --target 10.0.0.50:22 -c "admin:admin,root:toor,deploy:deploy123"

# Credentials file (user:pass per line)
brutus creds --target 10.0.0.50:3306 -C creds.txt

# Targets file (auto-fingerprinted with Nerva)
brutus creds --targets-file targets.txt -u admin -P passwords.txt

# Pipeline mode with Nerva JSON (HTTP and SNMP services are skipped)
naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt

# Pipe URI targets (protocol from scheme, no fingerprinting needed)
echo "ssh://192.168.1.10:22" | brutus creds -p "password,Password1"

# Import targets from nmap XML scan
brutus creds --nmap-file scan.xml -P passwords.txt

# Import targets from masscan (requires --protocol or auto-fingerprints with Nerva)
brutus creds --masscan-file scan.json --protocol ssh -P passwords.txt
```

## `brutus enum`

Enumerate accounts against account-existence oracles or Active Directory

- Usage: `brutus enum`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Account-existence oracle enumeration
brutus enum active oracles --domain praetorian.com -e test@praetorian.com --known-valid admin@praetorian.com

# Kerberos user enumeration
brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator

# Authenticate with Microsoft Entra ID via device code
brutus enum active teams auth --tenant contoso.com

# GitHub account enumeration by email
brutus enum active github -e alice@example.com,bob@example.com

# Generate emails for enumeration
brutus enum generate --domain example.com --format flast

# API-key OSINT/HUMINT sources (employee email/contact discovery)
brutus enum passive hunter --domain example.com
brutus enum passive apollo --domain example.com
brutus enum passive lusha --first-name Jane --last-name Doe --company "Example Inc"
brutus enum passive dehashed --domain example.com
```

## `brutus enum active`

Active account-existence enumeration against live oracles & directories

- Usage: `brutus enum active`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Account-existence oracle enumeration
brutus enum active oracles --domain example.com --known-valid admin@example.com

# Google Workspace account enumeration
brutus enum active google -e alice@example.com,bob@example.com

# Microsoft 365 account enumeration
brutus enum active microsoft365 -e alice@example.com,bob@example.com

# Kerberos user enumeration
brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator

# Authenticate with Microsoft Entra ID via device code
brutus enum active teams auth --tenant contoso.com

# GitHub account enumeration by email
brutus enum active github -e alice@example.com,bob@example.com

# Gravatar account enumeration by email
brutus enum active gravatar -e alice@example.com,bob@example.com

# Enumerate against a custom oracle definition
brutus enum active custom -f oracle.json -e jsmith,asmith
```

## `brutus enum active custom`

Run a declaratively-described enumeration oracle from a spec file

- Usage: `brutus enum active custom`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Domain for email generation (with --generate) |
| `--email-file` | `-E` | string |  | File of subjects to enumerate (one per line, use - for stdin) |
| `--emails` | `-e` | string |  | Comma-separated subjects (usernames or emails) to enumerate |
| `--file` | `-f` | string |  | Oracle spec file (JSON or YAML, required) |
| `--format` |  | string | `first.last` | Username format for generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--generate` |  | bool | `false` | Generate subjects from embedded name lists |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Run an oracle against inline subjects
brutus enum active custom -f oracle.json -e jsmith,asmith

# Run against a subject file
brutus enum active custom -f oracle.yaml -E users.txt

# Generate usernames and run
brutus enum active custom -f oracle.json --generate --format flast

# JSON output to a file
brutus enum active custom -f oracle.json -e jsmith -o results.jsonl
```

## `brutus enum active github`

Enumerate GitHub accounts by email (existence + username reveal)

- Usage: `brutus enum active github`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Generate candidate emails for this domain (statistically-likely first/last combos) |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to check |
| `--format` |  | string | `first.last` | Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--limit` |  | int | `0` | When generating with --domain, cap to the first N (most-likely) candidates (0 = all) |
| `--no-reveal` |  | bool | `false` | Skip username reveal after existence enumeration (existence-only; no token used, no temp repo created) |
| `--rotating-proxy` |  | bool | `false` | Signal that --proxy rotates exit IPs (e.g. Bright Data): reduces per-IP rate-limit backoff during GitHub existence enumeration (short retry delay, higher retry ceiling). No effect on token-rate-limited reveal. |
| `--token` |  | string |  | GitHub PAT for username reveal (overrides GITHUB_TOKEN; visible in process list — prefer the env var) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Existence-only enumeration (unauthenticated)
brutus enum active github -e alice@example.com,bob@example.com

# Generate candidate emails for a domain and enumerate the 5000 most likely
brutus enum active github --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active github -E emails.txt

# Reveal usernames for existing accounts (requires a PAT with repo+delete_repo)
export GITHUB_TOKEN=ghp_...
brutus enum active github -E emails.txt

# Pace requests to avoid GitHub's existence-endpoint rate limiting
brutus enum active github -E emails.txt --threads 2 --rate-limit 1
```

## `brutus enum active github map`

Correlate known emails to GitHub usernames (reveal-only, skips existence checks)

- Usage: `brutus enum active github map`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to correlate |
| `--token` |  | string |  | GitHub PAT (overrides GITHUB_TOKEN; visible in process list — prefer the env var) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--rotating-proxy` |  | bool | `false` | Signal that --proxy rotates exit IPs (e.g. Bright Data): reduces per-IP rate-limit backoff during GitHub existence enumeration (short retry delay, higher retry ceiling). No effect on token-rate-limited reveal. |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Correlate emails from a file (token from the environment)
export GITHUB_TOKEN=ghp_...
brutus enum active github map -E emails.txt

# Correlate a couple of emails inline
brutus enum active github map -e alice@example.com,bob@example.com
```

## `brutus enum active google`

Enumerate Google Workspace accounts (existence + SSO/IdP)

- Usage: `brutus enum active google`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Generate candidate emails for this domain (statistically-likely first/last combos) |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to check |
| `--format` |  | string | `first.last` | Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--limit` |  | int | `0` | When generating with --domain, cap to the first N (most-likely) candidates (0 = all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enumerate a couple of emails
brutus enum active google -e alice@example.com,bob@example.com

# Generate candidate emails for a domain and enumerate the 5000 most likely
brutus enum active google --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active google -E emails.txt

# Route through a SOCKS5 proxy and raise concurrency
brutus enum active google -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20
```

## `brutus enum active gravatar`

Enumerate accounts with a registered Gravatar (by email)

- Usage: `brutus enum active gravatar`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Generate candidate emails for this domain (statistically-likely first/last combos) |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to check |
| `--format` |  | string | `first.last` | Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--limit` |  | int | `0` | When generating with --domain, cap to the first N (most-likely) candidates (0 = all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enumerate a couple of emails
brutus enum active gravatar -e alice@example.com,bob@example.com

# Generate candidate emails for a domain and enumerate the 5000 most likely
brutus enum active gravatar --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active gravatar -E emails.txt

# Route through a SOCKS5 proxy and raise concurrency
brutus enum active gravatar -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20
```

## `brutus enum active kerberos`

Enumerate Active Directory users via Kerberos AS-REQ

- Usage: `brutus enum active kerberos`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--dc` |  | string |  | KDC (Domain Controller) address (host or host:port) |
| `--domain` | `-d` | string |  | Kerberos realm / AD domain (e.g., CORP.LOCAL) |
| `--user-file` | `-U` | string |  | File of usernames (one per line, use - for stdin) |
| `--users` | `-u` | string |  | Comma-separated usernames to enumerate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enumerate specific users
brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator,guest,krbtgt

# Enumerate from file
brutus enum active kerberos --dc dc01.corp.local --domain CORP.LOCAL -U users.txt

# Generate usernames and enumerate
brutus enum generate --format flast | brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -

# JSON output
brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator --json
```

## `brutus enum active microsoft365`

Enumerate Microsoft 365 accounts (existence + federation/tenant)

- Usage: `brutus enum active microsoft365`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Generate candidate emails for this domain (statistically-likely first/last combos) |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to check |
| `--format` |  | string | `first.last` | Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--limit` |  | int | `0` | When generating with --domain, cap to the first N (most-likely) candidates (0 = all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enumerate a couple of emails
brutus enum active microsoft365 -e alice@example.com,bob@example.com

# Generate candidate emails for a domain and enumerate the 5000 most likely
brutus enum active microsoft365 --domain target.com --format first.last --limit 5000

# Enumerate emails from a file
brutus enum active microsoft365 -E emails.txt

# Route through a SOCKS5 proxy and raise concurrency
brutus enum active microsoft365 -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20
```

## `brutus enum active oracles`

Enumerate which account-existence oracles work for an organization

- Usage: `brutus enum active oracles`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Domain to enumerate for DNS recon and email generation (defaults to the --known-valid email's domain) |
| `--email-file` | `-E` | string |  | File of emails to enumerate (one per line, use - for stdin) |
| `--emails` | `-e` | string |  | Comma-separated emails to enumerate |
| `--format` |  | string | `first.last` | Username format for generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--generate` |  | bool | `false` | Generate emails from embedded name lists |
| `--known-valid` |  | string |  | Known-valid email to validate oracles before enumeration (required) |
| `--services` | `-s` | string |  | Comma-separated oracles to check (default: all discovered/registered) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover candidate oracles via DNS and report which ones work
# (domain defaults to the --known-valid email's domain)
brutus enum active oracles --known-valid admin@praetorian.com

# Enumerate specific emails against the working oracles
brutus enum active oracles --domain praetorian.com -e test@praetorian.com,admin@praetorian.com --known-valid admin@praetorian.com

# Enumerate emails from file
brutus enum active oracles --domain praetorian.com -E emails.txt --known-valid admin@praetorian.com

# Generate emails and enumerate against working oracles
brutus enum active oracles --domain target.com --generate --format first.last --known-valid admin@target.com

# Check / enumerate against specific oracles only
brutus enum active oracles -e user@example.com -s microsoft365,google --known-valid admin@example.com

# JSON output
brutus enum active oracles --domain praetorian.com -e test@praetorian.com --known-valid admin@praetorian.com --json
```

## `brutus enum active oracles discover`

Discover working oracles by testing a known-valid email

- Usage: `brutus enum active oracles discover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Domain to discover candidate oracles from DNS TXT records |
| `--known-valid` |  | string |  | Known-valid email to test against oracles (required) |
| `--services` | `-s` | string |  | Comma-separated oracles to test (default: all registered) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Test oracles for a domain (auto-discovers candidate oracles from DNS)
brutus enum active oracles discover --domain praetorian.com --known-valid admin@praetorian.com

# Test specific oracles only
brutus enum active oracles discover --known-valid admin@example.com -s microsoft365,google
```

## `brutus enum active teams`

Microsoft Teams: device-code auth, user enumeration, and tenant posture audit

- Usage: `brutus enum active teams`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

## `brutus enum active teams audit`

Audit a Microsoft Teams tenant's external posture into graded findings

- Usage: `brutus enum active teams audit`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--access-token` |  | string |  | Access token to use (instead of device-code or --token-file) |
| `--client-id` |  | string | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Azure app (client) ID (device-code path) |
| `--email` |  | string |  | Single known-valid seed email address to audit (required) |
| `--include-consumer` |  | bool | `false` | Count consumer/personal (8:live:) Teams accounts as hits (default: only corporate 8:orgid: accounts) |
| `--no-browser` |  | bool | `false` | Don't automatically open the verification URL in a browser |
| `--no-presence` |  | bool | `false` | Skip Teams presence / out-of-office lookups (fewer requests; presence is gathered by default) |
| `--refresh-token` |  | string |  | Refresh token used to renew an expired access token |
| `--scope` |  | string | `offline_access https://api.spaces.skype.com/.default` | Space-separated OAuth2 scopes (device-code path) |
| `--tenant` |  | string | `organizations` | Tenant ID, domain, or "organizations"/"common" (device-code path) |
| `--token-file` |  | string |  | JSONL token file from "enum active teams auth -o" to reuse |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Audit a tenant via a single known-valid seed address (device-code auth inline)
brutus enum active teams audit --email alice@contoso.com

# Skip presence/out-of-office lookups (presence/OOO findings not evaluated)
brutus enum active teams audit --email alice@contoso.com --no-presence

# Reuse a token captured earlier with "enum active teams auth -o"
brutus enum active teams auth -o token.jsonl
brutus enum active teams audit --email alice@contoso.com --token-file token.jsonl

# Emit findings as JSONL
brutus enum active teams audit --email alice@contoso.com --json
```

## `brutus enum active teams auth`

Obtain Microsoft access token and refresh token via device code flow

- Usage: `brutus enum active teams auth`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--client-id` |  | string | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Azure app (client) ID |
| `--no-browser` |  | bool | `false` | Don't automatically open the verification URL in a browser |
| `--scope` | `-s` | string | `offline_access https://api.spaces.skype.com/.default` | Space-separated OAuth2 scopes |
| `--tenant` |  | string | `organizations` | Tenant ID, domain, or "organizations"/"common" |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Authenticate against the default (organizations / work-school) tenant (interactive)
brutus enum active teams auth

# Headless / SSH: print the URL and code, don't open a browser
brutus enum active teams auth --no-browser

# Authenticate against a specific tenant by domain
brutus enum active teams auth --tenant contoso.com

# Use a custom app registration and scopes
brutus enum active teams auth --client-id 00000000-0000-0000-0000-000000000000 \
  --scope "offline_access https://api.spaces.skype.com/.default"

# Capture the full token set as JSON
brutus enum active teams auth -o token.jsonl
```

## `brutus enum active teams users`

Enumerate corporate Microsoft Teams users by email address

- Usage: `brutus enum active teams users`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--access-token` |  | string |  | Access token to use (instead of device-code or --token-file) |
| `--client-id` |  | string | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Azure app (client) ID (device-code path) |
| `--domain` | `-d` | string |  | Generate candidate emails for this domain (statistically-likely first/last combos) |
| `--email-file` | `-E` | string |  | File of email addresses, one per line ("-" for stdin) |
| `--emails` | `-e` | string |  | Comma-separated email addresses to check |
| `--format` |  | string | `first.last` | Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--include-consumer` |  | bool | `false` | Count consumer/personal (8:live:) Teams accounts as hits (default: only corporate 8:orgid: accounts) |
| `--limit` |  | int | `0` | When generating with --domain, cap to the first N (most-likely) candidates (0 = all) |
| `--no-browser` |  | bool | `false` | Don't automatically open the verification URL in a browser |
| `--no-presence` |  | bool | `false` | Skip Teams presence / out-of-office lookups (fewer requests; presence is gathered by default) |
| `--refresh-token` |  | string |  | Refresh token used to renew an expired access token |
| `--scope` |  | string | `offline_access https://api.spaces.skype.com/.default` | Space-separated OAuth2 scopes (device-code path) |
| `--tenant` |  | string | `organizations` | Tenant ID, domain, or "organizations"/"common" (device-code path) |
| `--token-file` |  | string |  | JSONL token file from "enum active teams auth -o" to reuse |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Device-code auth inline, then enumerate a few emails
brutus enum active teams users -e alice@contoso.com,bob@contoso.com

# Generate candidate emails for a domain and enumerate the 5000 most likely
brutus enum active teams users --domain target.com --format first.last --limit 5000

# Generate first_last candidates (presence is fetched by default for hits)
brutus enum active teams users --domain target.com --format first_last

# Enumerate emails from a file, skipping presence lookups
brutus enum active teams users -E emails.txt --no-presence

# Reuse a token captured earlier with "enum active teams auth -o"
brutus enum active teams auth -o token.jsonl
brutus enum active teams users -E emails.txt --token-file token.jsonl

# Provide an access token directly
brutus enum active teams users -e alice@contoso.com --access-token "$TOKEN"

# Route through a SOCKS5 proxy and raise concurrency
brutus enum active teams users -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20
```

## `brutus enum apollo`

Discover people for a domain via Apollo.io (free; --enrich reveals emails)

- Usage: `brutus enum apollo`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use "brutus enum passive apollo" instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Apollo.io API key (overrides APOLLO_API_KEY; WARNING: visible in process list and shell history — prefer APOLLO_API_KEY) |
| `--domain` | `-d` | string |  | Company domain to discover people for (required) |
| `--enrich` |  | bool | `false` | Reveal emails for all discovered people via people/match (CONSUMES CREDITS; bounded by --limit) |
| `--limit` |  | int | `0` | Max people to discover AND (with --enrich) to reveal (bounds credit spend; 0 = no cap) |
| `--titles` |  | stringSlice | `[]` | Optional job-title filter (repeatable or comma-separated) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover people (DEFAULT — FREE, no credits; shows email/phone availability)
brutus enum passive apollo --domain example.com

# Filter by job titles
brutus enum passive apollo -d example.com --titles "VP Engineering" --titles "CTO"

# Enrich all discovered people (CONSUMES CREDITS, bounded by --limit)
brutus enum passive apollo -d example.com --enrich --limit 50

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive apollo -d example.com --api-key abc123
```

## `brutus enum dehashed`

Collect breach-exposed identity data for a domain via DeHashed

- Usage: `brutus enum dehashed`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use "brutus enum passive dehashed" instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--all-emails` |  | bool | `false` | Keep all emails, not just those @&lt;domain&gt; (disables corporate-only filtering) |
| `--api-key` |  | string |  | DeHashed API key (overrides DEHASHED_API_KEY; WARNING: visible in process list and shell history — prefer DEHASHED_API_KEY) |
| `--detailed` |  | bool | `false` | Emit a single structured JSON document with full per-contact detail (ip addresses, addresses, dobs, obtained dates) and run metadata |
| `--domain` | `-d` | string |  | Domain to search (required) |
| `--exclude-combolists` |  | bool | `false` | Drop records from known aggregator/combolist source databases (combolists are included by default) |
| `--limit` |  | int | `100` | Maximum number of records to collect (bounds credit spend) |
| `--no-credentials` |  | bool | `false` | Suppress breach-exposed plaintext passwords from the output |
| `--no-dedup` |  | bool | `false` | Do not merge records that share an email |
| `--sources` |  | stringSlice | `[]` | Restrict results to these DeHashed source databases (comma-separated, exact names) |
| `--with-credentials` |  | bool | `false` | Include breach-exposed plaintext passwords in --detailed output (off by default; hashes are never included) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Collect refined breach contacts for a domain (key from DEHASHED_API_KEY)
brutus enum passive dehashed --domain example.com

# Same, but suppress the breach-exposed plaintext passwords from output
brutus enum passive dehashed --domain example.com --no-credentials

# Keep every email (not just @example.com), unmerged; drop combolist DBs for clean identity-only enumeration
brutus enum passive dehashed -d example.com --all-emails --no-dedup --exclude-combolists

# Restrict to specific source databases (exact names, comma-separated)
brutus enum passive dehashed -d example.com --sources "Adobe,LinkedIn"

# Emit one structured JSON document with full per-contact detail + run metadata
brutus enum passive dehashed -d example.com --detailed -o breaches.json

# Same detailed export, including breach-exposed plaintext passwords
brutus enum passive dehashed -d example.com --detailed --with-credentials -o breaches.json

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive dehashed -d example.com --api-key abc123

# Cap results (and credit spend) and write JSONL to a file
brutus enum passive dehashed -d example.com --limit 50 -o breaches.jsonl
```

## `brutus enum generate`

Generate email addresses or usernames from embedded name lists

- Usage: `brutus enum generate`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | `-d` | string |  | Domain to append to generated usernames (omit to generate usernames only) |
| `--format` |  | string | `first.last` | Username format (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first) |
| `--limit` |  | int | `0` | Emit only the first N (most-likely) results (0 = no limit, emit all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Generate emails: jsmith@example.com
brutus enum generate --domain example.com --format flast

# Generate usernames only: jsmith
brutus enum generate --format flast

# Generate john.smith@example.com (default format)
brutus enum generate --domain example.com

# Emit only the 1000 most-likely emails
brutus enum generate --domain example.com --limit 1000

# Pipe the 500 most-likely usernames to Kerberos enum
brutus enum generate --format flast --limit 500 | brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -
```

## `brutus enum hunter`

Discover people and emails for a domain via Hunter.io Domain Search

- Usage: `brutus enum hunter`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use "brutus enum passive hunter" instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Hunter.io API key (overrides HUNTER_API_KEY; WARNING: visible in process list and shell history — prefer HUNTER_API_KEY) |
| `--domain` | `-d` | string |  | Domain to search (required) |
| `--limit` |  | int | `0` | Maximum number of people to return (0 = no cap, return all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover people for a domain (key from HUNTER_API_KEY)
brutus enum passive hunter --domain example.com

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive hunter -d example.com --api-key abc123

# JSONL output to a file
brutus enum passive hunter -d example.com -o people.jsonl
```

## `brutus enum lusha`

Enrich a single person identity to emails and phones via Lusha v3

- Usage: `brutus enum lusha`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use "brutus enum passive lusha" instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Lusha API key (overrides LUSHA_API_KEY; WARNING: visible in process list and shell history — prefer LUSHA_API_KEY) |
| `--company` |  | string |  | Company name (with the name pair) |
| `--domain` |  | string |  | Company domain (alternative to --company) |
| `--email` |  | string |  | Enrich by email address (mutually exclusive identity) |
| `--email-only` |  | bool | `false` | Request only email datapoints (mutually exclusive with --phone) |
| `--first-name` |  | string |  | First name (with --last-name and --company or --domain) |
| `--last-name` |  | string |  | Last name (with --first-name) |
| `--limit` |  | int | `0` | Roster mode (--domain only): max contacts to search + enrich; 0 = collect all (consumes ~1 credit/contact) |
| `--linkedin` |  | string |  | Enrich by LinkedIn profile URL (mutually exclusive identity) |
| `--phone` |  | bool | `false` | Request phone datapoints in addition to email |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enrich by name + company (key from LUSHA_API_KEY)
brutus enum passive lusha --first-name Ada --last-name Lovelace --company Analytical

# Enrich by name + company domain
brutus enum passive lusha --first-name Ada --last-name Lovelace --domain example.com

# Enrich by email
brutus enum passive lusha --email ada@example.com

# Enrich by LinkedIn URL, also request phone numbers
brutus enum passive lusha --linkedin https://linkedin.com/in/ada --phone

# Roster: enumerate an entire company by domain (collect all — consumes credits)
brutus enum passive lusha --domain example.com

# Roster: cap the roster (and credit spend) at 25 contacts
brutus enum passive lusha --domain example.com --limit 25

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive lusha --email ada@example.com --api-key abc123
```

## `brutus enum passive`

API-key OSINT/HUMINT sources — employee email/contact discovery & enrichment

- Usage: `brutus enum passive`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover people via Hunter.io
brutus enum passive hunter --domain example.com

# Discover and enrich people via Apollo.io
brutus enum passive apollo --domain example.com

# Enrich a contact via Lusha
brutus enum passive lusha --first-name Jane --last-name Doe --company "Example Inc"

# Collect breach-exposed identity data via DeHashed
brutus enum passive dehashed --domain example.com

# Scrape LinkedIn Sales Navigator profiles via PhantomBuster
brutus enum passive linkedin --agent-id 1234567890
```

## `brutus enum passive apollo`

Discover people for a domain via Apollo.io (free; --enrich reveals emails)

- Usage: `brutus enum passive apollo`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Apollo.io API key (overrides APOLLO_API_KEY; WARNING: visible in process list and shell history — prefer APOLLO_API_KEY) |
| `--domain` | `-d` | string |  | Company domain to discover people for (required) |
| `--enrich` |  | bool | `false` | Reveal emails for all discovered people via people/match (CONSUMES CREDITS; bounded by --limit) |
| `--limit` |  | int | `0` | Max people to discover AND (with --enrich) to reveal (bounds credit spend; 0 = no cap) |
| `--titles` |  | stringSlice | `[]` | Optional job-title filter (repeatable or comma-separated) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover people (DEFAULT — FREE, no credits; shows email/phone availability)
brutus enum passive apollo --domain example.com

# Filter by job titles
brutus enum passive apollo -d example.com --titles "VP Engineering" --titles "CTO"

# Enrich all discovered people (CONSUMES CREDITS, bounded by --limit)
brutus enum passive apollo -d example.com --enrich --limit 50

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive apollo -d example.com --api-key abc123
```

## `brutus enum passive dehashed`

Collect breach-exposed identity data for a domain via DeHashed

- Usage: `brutus enum passive dehashed`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--all-emails` |  | bool | `false` | Keep all emails, not just those @&lt;domain&gt; (disables corporate-only filtering) |
| `--api-key` |  | string |  | DeHashed API key (overrides DEHASHED_API_KEY; WARNING: visible in process list and shell history — prefer DEHASHED_API_KEY) |
| `--detailed` |  | bool | `false` | Emit a single structured JSON document with full per-contact detail (ip addresses, addresses, dobs, obtained dates) and run metadata |
| `--domain` | `-d` | string |  | Domain to search (required) |
| `--exclude-combolists` |  | bool | `false` | Drop records from known aggregator/combolist source databases (combolists are included by default) |
| `--limit` |  | int | `100` | Maximum number of records to collect (bounds credit spend) |
| `--no-credentials` |  | bool | `false` | Suppress breach-exposed plaintext passwords from the output |
| `--no-dedup` |  | bool | `false` | Do not merge records that share an email |
| `--sources` |  | stringSlice | `[]` | Restrict results to these DeHashed source databases (comma-separated, exact names) |
| `--with-credentials` |  | bool | `false` | Include breach-exposed plaintext passwords in --detailed output (off by default; hashes are never included) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Collect refined breach contacts for a domain (key from DEHASHED_API_KEY)
brutus enum passive dehashed --domain example.com

# Same, but suppress the breach-exposed plaintext passwords from output
brutus enum passive dehashed --domain example.com --no-credentials

# Keep every email (not just @example.com), unmerged; drop combolist DBs for clean identity-only enumeration
brutus enum passive dehashed -d example.com --all-emails --no-dedup --exclude-combolists

# Restrict to specific source databases (exact names, comma-separated)
brutus enum passive dehashed -d example.com --sources "Adobe,LinkedIn"

# Emit one structured JSON document with full per-contact detail + run metadata
brutus enum passive dehashed -d example.com --detailed -o breaches.json

# Same detailed export, including breach-exposed plaintext passwords
brutus enum passive dehashed -d example.com --detailed --with-credentials -o breaches.json

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive dehashed -d example.com --api-key abc123

# Cap results (and credit spend) and write JSONL to a file
brutus enum passive dehashed -d example.com --limit 50 -o breaches.jsonl
```

## `brutus enum passive hunter`

Discover people and emails for a domain via Hunter.io Domain Search

- Usage: `brutus enum passive hunter`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Hunter.io API key (overrides HUNTER_API_KEY; WARNING: visible in process list and shell history — prefer HUNTER_API_KEY) |
| `--domain` | `-d` | string |  | Domain to search (required) |
| `--limit` |  | int | `0` | Maximum number of people to return (0 = no cap, return all) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Discover people for a domain (key from HUNTER_API_KEY)
brutus enum passive hunter --domain example.com

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive hunter -d example.com --api-key abc123

# JSONL output to a file
brutus enum passive hunter -d example.com -o people.jsonl
```

## `brutus enum passive linkedin`

Scrape LinkedIn Sales Navigator profiles via PhantomBuster

- Usage: `brutus enum passive linkedin`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--agent-id` |  | string |  | PhantomBuster agent ID for the Sales Navigator scraper (required) |
| `--api-key` |  | string |  | PhantomBuster API key (overrides PHANTOMBUSTER_KEY; WARNING: visible in process list and shell history — prefer PHANTOMBUSTER_KEY) |
| `--result-file` |  | string | `result.csv` | Result filename to download from S3 (default: result.csv) |
| `--skip-launch` |  | bool | `false` | Skip launching the agent — fetch results from the most recent run instead |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Launch a Sales Nav scraper and fetch results
brutus enum passive linkedin --agent-id 1234567890

# Fetch results from a previous run (skip launching a new one)
brutus enum passive linkedin --agent-id 1234567890 --skip-launch

# Specify a custom result filename
brutus enum passive linkedin --agent-id 1234567890 --result-file result.json

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive linkedin --agent-id 1234567890 --api-key abc123
```

## `brutus enum passive lusha`

Enrich a single person identity to emails and phones via Lusha v3

- Usage: `brutus enum passive lusha`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Lusha API key (overrides LUSHA_API_KEY; WARNING: visible in process list and shell history — prefer LUSHA_API_KEY) |
| `--company` |  | string |  | Company name (with the name pair) |
| `--domain` |  | string |  | Company domain (alternative to --company) |
| `--email` |  | string |  | Enrich by email address (mutually exclusive identity) |
| `--email-only` |  | bool | `false` | Request only email datapoints (mutually exclusive with --phone) |
| `--first-name` |  | string |  | First name (with --last-name and --company or --domain) |
| `--last-name` |  | string |  | Last name (with --first-name) |
| `--limit` |  | int | `0` | Roster mode (--domain only): max contacts to search + enrich; 0 = collect all (consumes ~1 credit/contact) |
| `--linkedin` |  | string |  | Enrich by LinkedIn profile URL (mutually exclusive identity) |
| `--phone` |  | bool | `false` | Request phone datapoints in addition to email |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Enrich by name + company (key from LUSHA_API_KEY)
brutus enum passive lusha --first-name Ada --last-name Lovelace --company Analytical

# Enrich by name + company domain
brutus enum passive lusha --first-name Ada --last-name Lovelace --domain example.com

# Enrich by email
brutus enum passive lusha --email ada@example.com

# Enrich by LinkedIn URL, also request phone numbers
brutus enum passive lusha --linkedin https://linkedin.com/in/ada --phone

# Roster: enumerate an entire company by domain (collect all — consumes credits)
brutus enum passive lusha --domain example.com

# Roster: cap the roster (and credit spend) at 25 contacts
brutus enum passive lusha --domain example.com --limit 25

# Provide the key explicitly (note: visible in process list / shell history)
brutus enum passive lusha --email ada@example.com --api-key abc123
```

## `brutus logon`

Detect Windows logon-screen backdoors (runs both sticky keys and utilman)

- Usage: `brutus logon`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--exec` |  | string |  | Execute command via detected backdoor |
| `--experimental-ai` |  | bool | `false` | Enable Vision API for backdoor confirmation |
| `--fast` |  | bool | `false` | fast triage: shorter settle budget for internet-scale sweeps; reports HIGH/CRITICAL or indeterminate, never clean (rerun indeterminates without --fast for a careful verdict) |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--no-nla-probe` |  | bool | `false` | Disable the pre-WASM RDP negotiation probe (always run the full WASM session) |
| `--open` |  | bool | `false` | Auto-open browser when web terminal starts |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--scan-timeout` |  | duration | `10s` | Per-host settle/scan deadline (post-connect): how long to watch the logon screen after the trigger before deciding. Distinct from --connect-timeout (the TCP dial timeout). |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |
| `--web` |  | bool | `false` | Start interactive web terminal via detected backdoor |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Rejected flags

These flags reach `brutus logon` through inheritance, but the command refuses them:

| Flag | Why |
| --- | --- |
| `--timeout` | --timeout is not valid here; use --scan-timeout (settle deadline) and/or --connect-timeout (TCP connect) |

### Examples

```bash
# Detect sticky keys and utilman backdoors (heuristic)
brutus logon --target 10.0.0.50:3389

# Vision API confirmation (more accurate)
brutus logon --target 10.0.0.50:3389 --experimental-ai

# Execute a command via detected backdoor
brutus logon --target 10.0.0.50:3389 --exec "whoami"

# Interactive web terminal via backdoor
brutus logon --target 10.0.0.50:3389 --web --open

# Pipeline mode with Nerva JSON (only RDP targets are tested)
naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | brutus logon

# Pipe plain targets (auto-fingerprinted, only RDP services scanned)
echo "10.0.0.50:3389" | brutus logon

# Pipe URI targets
echo "rdp://10.0.0.50:3389" | brutus logon

# Import targets from nmap XML scan (only RDP services tested)
brutus logon --nmap-file scan.xml
```

## `brutus snmp`

Test SNMP community strings against targets

- Usage: `brutus snmp`
- Aliases: `community`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--community` | `-c` | string |  | Custom community strings (comma-separated) |
| `--community-file` | `-C` | string |  | Community string file (one per line) |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# Test with default community strings
brutus snmp --target 192.168.1.1:161

# Aggressive mode for comprehensive testing (~200+ strings)
brutus snmp --target 10.0.0.1:161 --mode aggressive

# Custom community strings
brutus snmp --target 192.168.1.1:161 -c "mycommunity,secretstring"

# Pipeline mode
naabu -host 10.0.0.0/24 -p 161 -silent | nerva --json | brutus snmp

# Targets file
brutus snmp --targets-file snmp-hosts.txt --mode aggressive

# Import targets from nmap XML scan (only SNMP services tested)
brutus snmp --nmap-file scan.xml --mode aggressive
```

## `brutus stickykeys`

Detect the Windows sticky-keys (sethc.exe) logon backdoor only

- Usage: `brutus stickykeys`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--exec` |  | string |  | Execute command via detected backdoor |
| `--experimental-ai` |  | bool | `false` | Enable Vision API for backdoor confirmation |
| `--fast` |  | bool | `false` | fast triage: shorter settle budget for internet-scale sweeps; reports HIGH/CRITICAL or indeterminate, never clean (rerun indeterminates without --fast for a careful verdict) |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--no-nla-probe` |  | bool | `false` | Disable the pre-WASM RDP negotiation probe (always run the full WASM session) |
| `--open` |  | bool | `false` | Auto-open browser when web terminal starts |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--scan-timeout` |  | duration | `10s` | Per-host settle/scan deadline (post-connect): how long to watch the logon screen after the trigger before deciding. Distinct from --connect-timeout (the TCP dial timeout). |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |
| `--web` |  | bool | `false` | Start interactive web terminal via detected backdoor |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Rejected flags

These flags reach `brutus stickykeys` through inheritance, but the command refuses them:

| Flag | Why |
| --- | --- |
| `--timeout` | --timeout is not valid here; use --scan-timeout (settle deadline) and/or --connect-timeout (TCP connect) |

### Examples

```bash
# Detect the sticky-keys backdoor only
brutus stickykeys --target 10.0.0.50:3389

# Vision API confirmation (more accurate)
brutus stickykeys --target 10.0.0.50:3389 --experimental-ai
```

## `brutus utilman`

Detect the Windows utilman (Ease of Access) logon backdoor only

- Usage: `brutus utilman`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--exec` |  | string |  | Execute command via detected backdoor |
| `--experimental-ai` |  | bool | `false` | Enable Vision API for backdoor confirmation |
| `--fast` |  | bool | `false` | fast triage: shorter settle budget for internet-scale sweeps; reports HIGH/CRITICAL or indeterminate, never clean (rerun indeterminates without --fast for a careful verdict) |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--no-nla-probe` |  | bool | `false` | Disable the pre-WASM RDP negotiation probe (always run the full WASM session) |
| `--open` |  | bool | `false` | Auto-open browser when web terminal starts |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--scan-timeout` |  | duration | `10s` | Per-host settle/scan deadline (post-connect): how long to watch the logon screen after the trigger before deciding. Distinct from --connect-timeout (the TCP dial timeout). |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |
| `--web` |  | bool | `false` | Start interactive web terminal via detected backdoor |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Rejected flags

These flags reach `brutus utilman` through inheritance, but the command refuses them:

| Flag | Why |
| --- | --- |
| `--timeout` | --timeout is not valid here; use --scan-timeout (settle deadline) and/or --connect-timeout (TCP connect) |

### Examples

```bash
# Detect the utilman backdoor only
brutus utilman --target 10.0.0.50:3389

# Vision API confirmation (more accurate)
brutus utilman --target 10.0.0.50:3389 --experimental-ai
```

## `brutus web`

Audit HTTP/web panel credentials (AI-powered or credential list)

- Usage: `brutus web`
- Aliases: `http`, `panels`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--browser-tabs` |  | int | `3` | Number of concurrent browser tabs |
| `--browser-timeout` |  | duration | `1m0s` | Total timeout for browser operations |
| `--browser-visible` |  | bool | `false` | Show browser window (demo mode) |
| `--connect-timeout` |  | duration | `3s` | TCP connect timeout for scan dials (separate from --scan-timeout, which is the per-host settle deadline). A reachable host completes the handshake in ~1 RTT, so the short default only accelerates dead-host rejection; raise it for high-latency target sets. |
| `--credentials` | `-c` | string |  | Comma-separated user:pass pairs (e.g., admin:admin,root:toor) |
| `--credentials-file` | `-C` | string |  | Credentials file (user:pass per line) |
| `--experimental-ai` |  | bool | `false` | Enable AI-powered credential detection and Vision verification |
| `--https` |  | bool | `false` | Use HTTPS for browser connections |
| `--masscan-file` |  | string |  | Masscan JSON file (-oJ output) to import targets from |
| `--mode` | `-m` | string | `default` | Aggressiveness tier: cautious, default, aggressive |
| `--nmap-file` |  | string |  | Nmap XML file (-oX output) to import targets from |
| `--protocol` |  | string |  | Protocol override (http or https) |
| `--retries` |  | int | `2` | Max retries on connection error (0 = disabled) |
| `--target` |  | string |  | Target host:port |
| `--targets-file` |  | string |  | File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set) |
| `--verify` |  | bool | `false` | Require strict TLS certificate verification |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--jitter` |  | duration | `0s` | Random delay variance for rate limiting |
| `--json` |  | bool | `false` | JSON output format |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output` | `-o` | string |  | Output file for JSON results (implies --json) |
| `--proxy` |  | string |  | Proxy URL. HTTP enum sources accept http, https, socks5, socks5h (a bare host:port defaults to http, like curl); raw-TCP scan plugins support socks5/socks5h only. Examples: --proxy http://host:8080, --proxy socks5://127.0.0.1:1080 |
| `--proxy-user` |  | string |  | Proxy credentials as user:pass (curl-style); takes precedence over credentials embedded in --proxy. Note: visible in process args/shell history. |
| `--quiet` | `-q` | bool | `false` | Quiet mode - only show successful credentials |
| `--rate-limit` |  | float64 | `0` | Max requests per second (0 = unlimited) |
| `--threads` | `-t` | int | `10` | Number of concurrent threads |
| `--timeout` |  | duration | `10s` | Per-target timeout |
| `--verbose` | `-v` | bool | `false` | Verbose mode - show detailed progress to stderr |

### Examples

```bash
# AI-powered credential detection (recommended)
brutus web --target 192.168.1.1:80 --experimental-ai

# Pipeline mode with Nerva JSON
naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | nerva --json | brutus web --experimental-ai

# Manual credential list
brutus web --target 192.168.1.1:80 -c "admin:admin,root:toor"
brutus web --target 192.168.1.1:80 -C creds.txt

# HTTPS target
brutus web --target 192.168.1.1:443 --https --experimental-ai

# Browser with visible window (demo mode)
brutus web --target 192.168.1.1:8080 --experimental-ai --browser-visible

# Import targets from nmap XML scan
brutus web --nmap-file scan.xml --experimental-ai
```
