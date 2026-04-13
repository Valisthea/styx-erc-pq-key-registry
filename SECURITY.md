# Security Policy

## Reporting a Vulnerability

**Critical vulnerabilities**: email **security@kairoslab.xyz** — do NOT open a public issue.

**Non-critical issues**: open a GitHub issue using the Security Vulnerability template.

## Scope

This repository contains interface specifications (Solidity `interface` files) and an EIP draft. There is no deployable contract code in this repo.

Security-relevant concerns include:

- Interface design flaws that would make correct implementation impossible or insecure
- Specification ambiguities that could lead to incompatible or vulnerable implementations
- Cryptographic assumptions in the spec that are incorrect or insufficiently documented
- EIP draft content that misrepresents algorithm properties (key sizes, security levels, NIST references)

## Response Timeline

| Severity | Initial response | Resolution target |
|----------|-----------------|-------------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 5 days | 30 days |
| Low | 14 days | Next release |

## Contact

Valisthea / Kairos Lab — security@kairoslab.xyz
