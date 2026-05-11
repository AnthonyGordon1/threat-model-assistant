# STRIDE Threat Modeling Framework

## Spoofing
Spoofing involves an attacker pretending to be someone or something else.
Examples: stealing credentials, forging tokens, impersonating users or services.
Mitigations: strong authentication, MFA, certificate pinning, signed tokens.
MITRE ATT&CK: T1078 Valid Accounts, T1539 Steal Web Session Cookie.

## Tampering
Tampering involves modifying data or code without authorization.
Examples: modifying database records, intercepting and altering network traffic, code injection.
Mitigations: input validation, integrity checks, digital signatures, checksums.
MITRE ATT&CK: T1565 Data Manipulation, T1190 Exploit Public-Facing Application.

## Repudiation
Repudiation involves denying that an action was performed.
Examples: user denies making a transaction, attacker covers their tracks by deleting logs.
Mitigations: audit logging, digital signatures, non-repudiation mechanisms, tamper-proof logs.
MITRE ATT&CK: T1070 Indicator Removal, T1562 Impair Defenses.

## Information Disclosure
Information disclosure involves exposing data to unauthorized parties.
Examples: data leakage, exposed API keys, verbose error messages, unencrypted storage.
Mitigations: encryption at rest and in transit, least privilege, proper error handling, secrets management.
MITRE ATT&CK: T1552 Unsecured Credentials, T1530 Data from Cloud Storage.

## Denial of Service
Denial of service involves making a system unavailable to legitimate users.
Examples: flooding a server with requests, resource exhaustion, crash exploits.
Mitigations: rate limiting, input validation, resource quotas, auto-scaling, WAF rules.
MITRE ATT&CK: T1499 Endpoint Denial of Service, T1498 Network Denial of Service.

## Elevation of Privilege
Elevation of privilege involves gaining higher permissions than intended.
Examples: SQL injection granting admin access, IDOR, broken access control, privilege escalation.
Mitigations: least privilege, RBAC, input sanitization, access control checks, parameter validation.
MITRE ATT&CK: T1548 Abuse Elevation Control Mechanism, T1134 Access Token Manipulation.