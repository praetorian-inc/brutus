# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Brutus, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report vulnerabilities via one of these methods:

1. **Email:** security@praetorian.com
2. **GitHub Security Advisory:** Use the "Report a vulnerability" button in the Security tab

### What to Include

Please provide:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if you have one)
5. **Your contact information** for follow-up

### Response Timeline

| Action | Timeline |
|--------|----------|
| Initial response | 24-48 hours |
| Vulnerability assessment | 1 week |
| Fix development | 2-4 weeks |
| Public disclosure | After fix is released |

### What to Expect

1. **Acknowledgment** within 48 hours
2. **Assessment** of severity and impact
3. **Regular updates** on fix progress
4. **Credit** in release notes (unless you prefer anonymity)

## Security Considerations for Users

### Authorized Use Only

Brutus is designed for **authorized security testing only**. Use it only on systems you own or have explicit permission to test.

**Authorized uses:**
- Penetration testing with written authorization
- Security research in controlled environments
- CTF competitions
- Testing your own systems

**Prohibited uses:**
- Unauthorized access attempts
- Testing systems without permission
- Malicious activities

### Operational Security

When using Brutus:

1. **Limit thread count** to avoid overwhelming targets
2. **Use appropriate timeouts** to prevent detection
3. **Log responsibly** - don't store credentials in plaintext
4. **Secure your wordlists** - treat them as sensitive data
5. **Use VPN/Tor** when appropriate for your engagement

### Credential Handling

Brutus is designed to minimize credential exposure:

- Passwords are never logged by default
- Results can be filtered to exclude passwords in output
- Credentials may remain in memory until garbage collection (see Memory Security)

### Network Considerations

- Configure appropriate **firewall rules** for your test environment
- Use **network segmentation** when testing in production
- Monitor for **IDS/IPS alerts** during testing

## Known Security Limitations

### No Encryption at Rest

Brutus does not encrypt:
- Configuration files
- Wordlist files
- Output files

**Mitigation:** Use full-disk encryption and proper file permissions.

### TLS Certificate Validation

By default, TLS is disabled unless the protocol requires it. There is no `--insecure` flag. Pass `--verify` to opt in to strict certificate verification.

**Recommendation:** Use `--verify` when connecting over TLS and certificate validation is expected.

### Memory Security

Credentials may remain in memory until garbage collection. Brutus does not currently:
- Use secure memory allocation
- Zero memory after use

**Mitigation:** Run Brutus in isolated environments.

## Security Features

### Rate Limiting

Configure thread counts and timeouts to avoid:
- Denial of service
- Account lockouts
- Detection by security tools

```go
config := &brutus.Config{
    Threads: 5,                // Conservative
    Timeout: 3 * time.Second,  // Short timeout
}
```

### Clear Error Semantics

Brutus distinguishes between:
- Authentication failures (no error logged)
- Connection errors (error logged)

This helps avoid false positives and unnecessary alerts.

### Context Cancellation

All operations support context cancellation for:
- Graceful shutdown
- Timeout enforcement
- Resource cleanup

## Dependency Security

### Supply Chain

- All dependencies are from trusted sources
- Dependencies are pinned to specific versions
- Regular dependency updates via Dependabot

### Build Security

- Reproducible builds
- No CGO dependencies
- Static binary compilation

## Security Updates

Security updates are released as:

1. **Patch versions** for security fixes (e.g., 1.0.1)
2. **Security advisories** on GitHub
3. **Email notifications** to subscribers

### Staying Updated

```bash
# Check for updates
go list -m -u github.com/praetorian-inc/brutus

# Update to latest
go get -u github.com/praetorian-inc/brutus@latest
```

## Compliance

Brutus is designed to support compliance requirements:

### PCI DSS

- Credential testing for PCI assessments
- Default credential detection
- Documentation for audit trails

### SOC 2

- Authorized testing capabilities
- Audit logging support
- Access control integration

### NIST

- Supports NIST 800-53 assessment procedures
- Credential policy validation
- Security control testing

## Contact

- **Security issues:** security@praetorian.com
- **General questions:** Open a GitHub issue
- **Commercial support:** https://www.praetorian.com/contact

## Acknowledgments

We thank the following security researchers for responsible disclosure:

*No vulnerabilities reported yet.*

---

**Remember:** With great power comes great responsibility. Use Brutus ethically and legally.
