# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: **contact@hdds.io**

Include the following information:

- Type of vulnerability (e.g., buffer overflow, injection, DoS)
- Full path of the affected source file(s)
- Location of the affected code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity (critical: 7 days, high: 30 days, medium: 90 days)
- **Public Disclosure**: Coordinated with you after fix is available

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and data destruction
- Only interact with accounts they own or with explicit permission
- Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue
- Report vulnerabilities promptly and do not publicly disclose before resolution

## Security Best Practices for Users

### Network Security

- Use TLS for all network communications in production
- Configure proper firewall rules for DDS ports (default: 7400-7500)
- Use DDS Security plugins when available

### Configuration

- Review QoS settings for your security requirements
- Enable authentication and access control in production
- Regularly update to the latest stable version

## Known Security Considerations

### DDS Protocol

HDDS implements the DDS-RTPS protocol which, by default, does not encrypt traffic. For sensitive deployments:

- Use the DDS Security specification (when implemented)
- Deploy in isolated networks
- Use VPN or other network-level encryption

### Memory Safety

HDDS is written in Rust, providing memory safety guarantees. However:

- Some `unsafe` code exists for performance-critical paths
- All `unsafe` blocks are documented with safety justifications
- We welcome security audits of unsafe code sections

## Acknowledgments

We thank all security researchers who help keep HDDS secure. Contributors who report valid security issues will be acknowledged here (with permission).
