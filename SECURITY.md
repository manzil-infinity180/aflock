# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in aflock, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **cole@testifysec.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Best Practices

aflock is a security-critical tool that enforces policy on AI agent behavior. We take the following measures:

- All changes to `main` require PR review and passing CI
- Dependencies are regularly audited
- Code is linted with golangci-lint using strict rules
- Integration tests verify policy enforcement behavior
