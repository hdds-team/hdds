# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| < 1.5   | :x:                |

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
- Configure proper firewall rules for DDS ports (RTPS port base 7400, 250 ports per domain id: domain 0 uses 7400-7649, domain 1 uses 7650-7899, and so on)
- Use DDS Security plugins when available

### Configuration

- Review QoS settings for your security requirements
- Enable authentication and access control in production
- Regularly update to the latest stable version

## Known Security Considerations

### DDS Protocol

HDDS implements the DDS-RTPS protocol which, by default, does not encrypt traffic. For sensitive deployments:

- Enable DDS Security (the `security` cargo feature: authentication, access control and encryption)
- Deploy in isolated networks
- Use VPN or other network-level encryption

### DDS Security Known Limitations

- **Control submessages of user endpoints are not authenticated.** Metadata
  protection and RTPS (whole-message) protection are not implemented, so
  HEARTBEAT, GAP, ACKNACK and the end-of-coherent-set marker of user writers
  and readers travel unauthenticated. An on-path attacker who knows a writer
  GUID can truncate a coherent set (a reader delivers part of it as complete)
  and make a reader drop the next genuine sample of that writer. No
  unauthenticated data is delivered. A governance document that requests
  metadata or RTPS protection is refused at participant creation.
- **A directly created authentication plugin reads the CRL once.**
  `create_authentication_plugin` and `X509AuthenticationPlugin::new`, used
  outside a participant, read the certificate revocation list when they are
  called. An embedder must create the plugin again after every CRL rotation.
  A participant re-reads its CRL on its own.
- **Source filtering is not supported in 1.5.0.** `HDDS_SOURCE_ALLOW` and
  `HDDS_SOURCE_DENY` are refused: setting either makes participant creation
  fail, so a deployment cannot believe it filters sources when it does not.
  Use a network firewall or DDS Security access control instead.

See [docs/security-guide.md](docs/security-guide.md#known-limitations) for the full list of known limitations.

### Memory Safety

HDDS is written in Rust, providing memory safety guarantees. However:

- Some `unsafe` code exists for performance-critical paths
- New `unsafe` blocks must carry a `// SAFETY:` justification (see CONTRIBUTING.md)
- We welcome security audits of unsafe code sections

## Acknowledgments

We thank all security researchers who help keep HDDS secure. Contributors who report valid security issues will be acknowledged here (with permission).
