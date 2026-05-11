# STRIDE Threat Modeling Framework — Expanded Reference

## Overview
STRIDE is a threat modeling framework developed by Microsoft. Each letter represents a category of security threat. Use STRIDE to systematically identify threats during design reviews, feature development, and security assessments.

---

## S — Spoofing

### What it is
Spoofing involves an attacker pretending to be someone or something they are not — a user, a service, or a system component. The attacker gains trust they haven't earned.

### Why it matters
Once an attacker successfully spoofs an identity, they inherit all the trust and permissions of that identity. A spoofed admin account gives full system access. A spoofed internal service can make privileged API calls.

### Attack Mechanisms

**Credential theft and reuse**
Attacker steals valid credentials through phishing, data breaches, or credential stuffing using leaked password databases. Uses those credentials to authenticate as the victim.

**JWT algorithm confusion (RS256 to HS256)**
When a server accepts both RS256 and HS256, attacker obtains the public key (often at /.well-known/jwks.json), creates a forged token with alg changed to HS256, signs it using the public key as the HMAC secret. Server verifies it successfully.

**JWT alg:none attack**
Attacker decodes a valid JWT, modifies the payload to elevate privileges, sets alg to none, removes the signature. If the server accepts alg:none, the forged token is accepted without any signature verification.

**Session fixation**
Attacker sets a known session ID before the victim authenticates. After login, the server uses the attacker-controlled session ID, giving the attacker full access to the authenticated session.

**Cookie theft via XSS**
Attacker injects JavaScript that reads document.cookie or localStorage and exfiltrates tokens to an attacker-controlled server.

**MFA fatigue**
Attacker repeatedly sends MFA push notifications until the victim approves one out of frustration or confusion. No technical exploitation required — pure social engineering.

**DNS spoofing**
Attacker poisons DNS cache to redirect traffic from a legitimate domain to an attacker-controlled server. Victims connect thinking they are talking to the real service.

### Real World Examples

**Uber 2022 — MFA Fatigue**
Attacker purchased stolen credentials on the dark web. Sent repeated MFA push notifications to an Uber employee at 1am claiming to be Uber IT support. Employee approved the notification. Attacker gained access to internal tools including AWS, Google Cloud, Slack, and HackerOne bug reports.
Cost: $3.3 million regulatory investigation, significant reputational damage.

**LastPass 2022 — Developer Credential Theft**
Attacker compromised a DevOps engineer's home computer, stole their master password, and used it to access a shared cloud storage containing encrypted customer vault backups. Attacker then had unlimited time to brute force individual vault passwords offline.
Cost: $100 million in customer losses estimated, multiple class action lawsuits.

**GitHub 2022 — OAuth Token Theft**
Attacker stole OAuth user tokens issued to Heroku and Travis-CI integrations. Used tokens to download private repositories including some that contained AWS credentials. Pivoted to AWS to steal additional data.

### Code Examples

**Vulnerable — JWT accepting multiple algorithms:**
```javascript
const decoded = jwt.verify(token, secret, {
    algorithms: ['HS256', 'RS256', 'none']
});
```

**Secure — enforce a single algorithm:**
```javascript
const decoded = jwt.verify(token, publicKey, {
    algorithms: ['RS256']
});
```

**Vulnerable — token in localStorage:**
```javascript
localStorage.setItem('jwt', token);
const token = localStorage.getItem('jwt');
```

**Secure — HttpOnly cookie:**
```javascript
res.cookie('token', jwt, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
});
```

### Kill Chain Stages
Spoofing typically enables: Initial Access → Privilege Escalation → Lateral Movement

### MITRE ATT&CK Mappings
- T1078 Valid Accounts
- T1539 Steal Web Session Cookie
- T1621 Multi-Factor Authentication Request Generation
- T1556 Modify Authentication Process
- T1110 Brute Force

### Mitigations
- Enforce MFA with number matching on all accounts
- Use hardware security keys for privileged access
- Implement anomaly detection on authentication patterns
- Rate limit login and MFA verification endpoints
- Store tokens in HttpOnly cookies, never localStorage
- Enforce a single JWT signing algorithm per endpoint
- Check passwords against known breach databases (HaveIBeenPwned API)
- Implement DMARC, DKIM, and SPF to prevent email spoofing

---

## T — Tampering

### What it is
Tampering involves unauthorized modification of data, code, or system components. The attacker changes something they should not have access to — database records, files, network traffic, or application code.

### Why it matters
Tampered data undermines the integrity of your entire system. Financial records can be altered, audit logs erased, malicious code injected. Unlike data theft, tampering can be invisible — you may never know it happened.

### Attack Mechanisms

**SQL injection**
Attacker injects malicious SQL into input fields that gets executed by the database. Can read, modify, or delete any data the database user has access to.

**Command injection**
Attacker injects OS commands into input that gets passed to a shell. Achieves remote code execution on the server.

**Web shell upload**
Attacker uploads a server-side script disguised as an image or document. If stored in a web-accessible directory, visiting the URL executes the script, giving the attacker a persistent backdoor.

**Man-in-the-middle (MITM)**
Attacker intercepts network traffic and modifies data in transit. Requires position on the network or successful TLS downgrade attack.

**Insecure deserialization**
Attacker crafts malicious serialized objects that execute code when deserialized by the application. Python pickle, Java serialization, and PHP unserialize are common vectors.

**Dependency confusion / supply chain tampering**
Attacker publishes a malicious package with the same name as an internal private package. Build systems that check public registries first download and execute the malicious package.

**Path traversal**
Attacker uses sequences like ../../ in filenames or paths to write files to unintended locations on the server, including overwriting system files or planting web shells.

### Real World Examples

**Equifax 2017 — SQL Injection via Apache Struts**
An unpatched Apache Struts vulnerability (CVE-2017-5638) allowed remote code execution via a malicious Content-Type header. Attackers exfiltrated 147 million records over 76 days before detection. The patch had been available for 2 months before the breach.
Cost: $575 million FTC settlement, $1.38 billion total costs.

**SolarWinds 2020 — Supply Chain Tampering**
Nation-state attackers (APT29/Cozy Bear) compromised the SolarWinds build pipeline and injected malicious code (SUNBURST) into the Orion software update. The backdoor was signed with SolarWinds' legitimate certificate and distributed to 18,000 organizations including US government agencies.
Cost: $40 million incident response costs, $90 million total, 100+ government agencies compromised.

**British Airways 2018 — JavaScript Injection (Magecart)**
Attackers injected 22 lines of JavaScript into the British Airways payment page. The script skimmed payment card details and session tokens for 2 weeks before discovery.
Cost: £20 million GDPR fine (reduced from initial £183 million notice).

### Code Examples

**Vulnerable — SQL injection:**
```javascript
const query = `SELECT * FROM users WHERE email = '${email}'`;
// Attack: email = ' OR '1'='1' --
```

**Secure — parameterized query:**
```javascript
const query = 'SELECT * FROM users WHERE email = ?';
db.execute(query, [email]);
```

**Vulnerable — insecure deserialization:**
```python
import pickle
data = pickle.loads(user_input)
```

**Secure — use JSON for untrusted input:**
```python
import json
data = json.loads(user_input)
```

**Vulnerable — command injection:**
```javascript
exec(`ping ${userInput}`);
```

**Secure — avoid shell, use safe APIs:**
```javascript
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', validatedHost], callback);
```

### Kill Chain Stages
Tampering typically enables: Initial Access → Execution → Persistence → Impact

### MITRE ATT&CK Mappings
- T1190 Exploit Public-Facing Application
- T1505 Server Software Component
- T1565 Data Manipulation
- T1195 Supply Chain Compromise
- T1059 Command and Scripting Interpreter

### Mitigations
- Use parameterized queries and ORMs — never concatenate user input into SQL
- Validate and sanitize all user input server-side
- Never deserialize untrusted data using pickle or Java serialization
- Store uploads outside the web root, serve through CDN
- Verify file type by reading magic bytes not extension
- Implement code signing and artifact integrity checks in CI/CD
- Use software composition analysis (SCA) to detect compromised dependencies
- Enable TLS 1.2+ everywhere, enforce HSTS

---

## R — Repudiation

### What it is
Repudiation involves an attacker (or user) denying that an action occurred. Without proper logging and non-repudiation controls, you cannot prove who did what or when — making incident response, forensics, and legal action impossible.

### Why it matters
Repudiation is the gap between something happening and you being able to prove it happened. In a breach investigation, if you cannot reconstruct the attacker's actions, you cannot determine the blast radius, notify affected users accurately, or satisfy regulatory requirements.

### Attack Mechanisms

**Log tampering and deletion**
After gaining access, attacker deletes or modifies application and system logs to cover their tracks. If logs are stored on the same system being attacked, this is trivial.

**Log injection**
Attacker injects fake log entries containing newlines to forge legitimate-looking audit records or corrupt log parsers. Can be used to hide malicious activity in noise.

**Timestamp manipulation**
Attacker modifies system clock or crafts requests with fake timestamps to confuse forensic timelines.

**Exploiting missing logging**
Attacker performs malicious actions on endpoints that generate no log output. No evidence is created because the application never logged the event.

**Session hijacking without detection**
If session tokens are not logged on creation and use, an attacker using a stolen token generates activity indistinguishable from the legitimate user.

### Real World Examples

**Yahoo 2014 — Undetected Breach for 2 Years**
500 million accounts were compromised but not discovered until 2016 when stolen credentials appeared on a dark web marketplace. The absence of adequate logging and monitoring meant the breach was invisible to Yahoo's security team for 24 months.
Cost: $350 million reduction in Verizon acquisition price, $85 million class action settlement.

**Target 2013 — HVAC Vendor Credential Theft**
Attackers used credentials stolen from an HVAC vendor to access Target's network. Once inside, they installed malware on point-of-sale systems. The activity was logged but the security team did not investigate alerts. 40 million credit cards stolen.
Cost: $18.5 million multistate settlement, $202 million total.

**Uber 2016 — Breach Concealment**
After a breach exposing 57 million records, Uber paid the attackers $100,000 via their bug bounty program to delete the data and stay silent. Uber concealed the breach from regulators for over a year — a violation of breach notification laws.
Cost: $148 million settlement for breach concealment, FTC investigation.

### Code Examples

**Vulnerable — no logging on sensitive actions:**
```javascript
app.post('/api/transfer', authenticate, async (req, res) => {
    await transfer(req.user.id, req.body.toAccount, req.body.amount);
    res.json({ success: true });
    // No log — who transferred what to whom?
});
```

**Secure — structured audit logging:**
```javascript
app.post('/api/transfer', authenticate, async (req, res) => {
    await transfer(req.user.id, req.body.toAccount, req.body.amount);
    auditLog.info('funds_transferred', {
        userId: req.user.id,
        toAccount: req.body.toAccount,
        amount: req.body.amount,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
        requestId: req.id
    });
    res.json({ success: true });
});
```

**Secure — append-only log storage (AWS CloudWatch example):**
```javascript
// CloudWatch log streams are append-only by default
// Restrict DeleteLogGroup and DeleteLogStream IAM permissions
const logClient = new CloudWatchLogsClient({ region: 'us-east-1' });
await logClient.send(new PutLogEventsCommand({
    logGroupName: '/app/audit',
    logStreamName: 'transfers',
    logEvents: [{ timestamp: Date.now(), message: JSON.stringify(event) }]
}));
```

### Kill Chain Stages
Repudiation attacks typically occur during: Execution → Defense Evasion → Impact

### MITRE ATT&CK Mappings
- T1070 Indicator Removal
- T1562 Impair Defenses
- T1565 Data Manipulation
- T1491 Defacement

### Mitigations
- Log all authentication events, data access, and mutations with full context
- Store logs in an append-only system separate from the application
- Implement tamper-evident logging using cryptographic signatures
- Alert on log gaps — missing logs are as suspicious as malicious ones
- Retain logs for minimum 90 days (GDPR) to 1 year (PCI-DSS)
- Use digital signatures on critical transactions for non-repudiation
- Implement SIEM correlation rules to detect anomalous activity patterns

---

## I — Information Disclosure

### What it is
Information disclosure involves exposing data to parties who should not have access to it — through data leakage, insecure storage, verbose error messages, or unauthorized access to files and APIs.

### Why it matters
Disclosed information fuels every other attack. Leaked credentials enable spoofing. Disclosed architecture details enable targeted exploitation. Exposed PII triggers regulatory fines. Information disclosure is often the first step in a multi-stage attack chain.

### Attack Mechanisms

**Verbose error messages**
Application returns stack traces, database query errors, or internal paths in HTTP responses. Attacker learns the technology stack, file paths, and code structure.

**IDOR — Insecure Direct Object Reference**
Attacker manipulates object IDs in API requests to access other users' data. GET /api/invoices/1001 becomes GET /api/invoices/1002.

**S3 bucket misconfiguration**
Public S3 buckets allow unauthenticated listing and download of all stored objects. Automated tools scan for misconfigured buckets by guessing common names.

**Path traversal**
Attacker uses ../../ sequences to read files outside the intended directory. GET /files?name=../../etc/passwd returns the system password file.

**SSRF — Server Side Request Forgery**
Attacker tricks the server into making requests to internal services or cloud metadata endpoints. On AWS, http://169.254.169.254/latest/meta-data/iam/security-credentials/ returns IAM credentials.

**Exposed secrets in code**
API keys, database credentials, and private keys committed to public repositories. Automated scanners (GitGuardian, truffleHog) continuously monitor GitHub for exposed secrets.

**Unencrypted data at rest or in transit**
Sensitive data stored without encryption or transmitted over HTTP. Attacker intercepts or reads storage directly.

### Real World Examples

**Capital One 2019 — SSRF to S3**
Former AWS employee exploited a misconfigured WAF to perform SSRF against the EC2 metadata service. Retrieved IAM credentials and used them to list and download 30 folders from S3 containing 100 million customer applications.
Cost: $80 million OCC fine, $190 million class action settlement.

**Twitch 2021 — Internal Code Leak**
A misconfigured server allowed access to 125GB of internal Twitch data including the entire source code, creator payout data, and internal security tools. Posted publicly on 4chan.
Cost: Undisclosed, significant competitive and reputational damage.

**Verkada 2021 — Exposed Admin Credentials**
A hacker collective found Verkada's admin credentials in a publicly accessible Jenkins server log. Used them to access 150,000 security cameras inside hospitals, prisons, Tesla factories, and Cloudflare offices.
Cost: $3 million SEC fine for Verkada executives, significant regulatory action.

### Code Examples

**Vulnerable — stack trace in response:**
```javascript
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack });
});
```

**Secure — generic error, detailed server-side logging:**
```javascript
app.use((err, req, res, next) => {
    logger.error({ err, requestId: req.id, userId: req.user?.id });
    res.status(500).json({ error: 'An unexpected error occurred', requestId: req.id });
});
```

**Vulnerable — IDOR:**
```javascript
app.get('/api/documents/:id', authenticate, async (req, res) => {
    const doc = await Document.findById(req.params.id);
    res.json(doc);
});
```

**Secure — scope to authenticated user:**
```javascript
app.get('/api/documents/:id', authenticate, async (req, res) => {
    const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
});
```

**Vulnerable — path traversal:**
```javascript
app.get('/files', (req, res) => {
    res.sendFile(path.join('./uploads', req.query.name));
});
```

**Secure — validate resolved path:**
```javascript
app.get('/files', (req, res) => {
    const requestedPath = path.resolve('./uploads', req.query.name);
    if (!requestedPath.startsWith(path.resolve('./uploads'))) {
        return res.status(400).json({ error: 'Invalid path' });
    }
    res.sendFile(requestedPath);
});
```

### Kill Chain Stages
Information disclosure typically enables: Reconnaissance → Initial Access → Credential Access → Exfiltration

### MITRE ATT&CK Mappings
- T1552 Unsecured Credentials
- T1530 Data from Cloud Storage
- T1083 File and Directory Discovery
- T1213 Data from Information Repositories
- T1592 Gather Victim Host Information

### Mitigations
- Return generic error messages in production — log details server-side only
- Encrypt all sensitive data at rest and in transit
- Implement object-level authorization on every API endpoint
- Validate and sanitize file paths before access
- Enforce IMDSv2 on all EC2 instances to block SSRF to metadata service
- Scan repositories for secrets with Gitleaks or GitGuardian
- Block public S3 bucket access at the organization level
- Use AWS Config rules to alert on misconfigured resources

---

## D — Denial of Service

### What it is
Denial of Service involves making a system unavailable to legitimate users by exhausting resources — CPU, memory, bandwidth, database connections, or rate limits.

### Why it matters
Availability is a core security property. A service that is down cannot serve customers, generate revenue, or fulfill its purpose. DoS attacks are increasingly used as distractions during data breaches — security teams focus on the outage while the real attack happens elsewhere.

### Attack Mechanisms

**Volumetric DDoS**
Attacker floods the target with massive amounts of traffic from botnets, overwhelming network bandwidth and infrastructure capacity.

**Application layer DDoS (Layer 7)**
Attacker sends computationally expensive requests — complex searches, large file uploads, heavy database queries — that consume disproportionate server resources relative to the cost of sending them.

**Slowloris**
Attacker opens many connections to the server and sends partial HTTP headers very slowly, keeping connections open and exhausting the connection pool without sending much data.

**Regular expression DoS (ReDoS)**
Attacker sends input that triggers catastrophic backtracking in poorly written regular expressions, consuming 100% CPU for extended periods.

**Resource exhaustion via missing rate limiting**
Attacker submits thousands of password reset requests, file uploads, or API calls per minute. Without rate limiting, the server processes all of them, exhausting CPU, memory, and database connections.

**Zip bomb**
Attacker uploads a tiny archive file that decompresses to petabytes of data. If the application decompresses before checking size, it exhausts disk and memory.

### Real World Examples

**GitHub 2018 — Largest DDoS in History (at the time)**
GitHub was hit with a 1.35 Tbps memcached amplification attack. Attackers spoofed GitHub's IP address and sent small requests to misconfigured memcached servers, which responded with amplified traffic to GitHub. GitHub mitigated it in 8 minutes using Akamai Prolexic.
Cost: 8-minute outage, significant emergency response costs.

**AWS 2020 — 2.3 Tbps DDoS**
An unnamed AWS customer was targeted with a 2.3 Tbps CLDAP reflection/amplification attack — the largest ever recorded at that time. AWS Shield mitigated it over 3 days.

**Cloudflare 2023 — HTTP/2 Rapid Reset**
Attackers exploited a vulnerability in the HTTP/2 protocol (CVE-2023-44487) to send millions of requests per second using just a handful of connections. Peak: 201 million requests per second against a single target.

### Code Examples

**Vulnerable — no rate limiting on expensive endpoint:**
```javascript
app.post('/api/search', async (req, res) => {
    const results = await db.query(`SELECT * FROM products WHERE name LIKE '%${req.body.query}%'`);
    res.json(results);
});
```

**Secure — rate limiting with express-rate-limit:**
```javascript
const rateLimit = require('express-rate-limit');
const searchLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: 'Too many requests'
});
app.post('/api/search', searchLimiter, async (req, res) => {
    const results = await db.query('SELECT * FROM products WHERE name LIKE ?', [`%${req.body.query}%`]);
    res.json(results);
});
```

**Vulnerable — ReDoS:**
```javascript
const vulnerable = /^(a+)+$/;
vulnerable.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX'); // Hangs
```

**Secure — use safe regex or set timeout:**
```javascript
// Avoid nested quantifiers. Use specific character classes.
const safe = /^[a-z]{1,100}$/i;
```

**Vulnerable — zip bomb:**
```python
import zipfile
with zipfile.ZipFile(uploaded_file) as zf:
    zf.extractall('/tmp/uploads')  # No size check
```

**Secure — check compressed and decompressed size:**
```python
MAX_DECOMPRESSED = 50 * 1024 * 1024  # 50MB
with zipfile.ZipFile(uploaded_file) as zf:
    total_size = sum(info.file_size for info in zf.infolist())
    if total_size > MAX_DECOMPRESSED:
        raise ValueError("Archive too large")
    zf.extractall('/tmp/uploads')
```

### Kill Chain Stages
DoS attacks typically represent: Impact — or serve as a Distraction during: Execution → Exfiltration

### MITRE ATT&CK Mappings
- T1499 Endpoint Denial of Service
- T1498 Network Denial of Service
- T1496 Resource Hijacking
- T1489 Service Stop

### Mitigations
- Implement rate limiting on all public endpoints
- Use a CDN with DDoS protection (Cloudflare, AWS Shield, Akamai)
- Set request timeouts and body size limits
- Validate input size before processing archives or uploads
- Test regular expressions for catastrophic backtracking
- Implement auto-scaling to absorb traffic spikes
- Use connection limits and backpressure in API gateways

---

## E — Elevation of Privilege

### What it is
Elevation of privilege involves an attacker gaining higher permissions than they are supposed to have — a regular user accessing admin functions, a low-privilege process reading root-owned files, or an anonymous user accessing authenticated resources.

### Why it matters
Privilege escalation is the multiplier for every other attack. Initial access rarely gives an attacker everything they want. By escalating privileges they can access more data, disable security controls, create backdoor accounts, and pivot to other systems.

### Attack Mechanisms

**Broken access control (IDOR)**
Attacker accesses objects belonging to other users by manipulating IDs in API requests. Horizontal privilege escalation — same privilege level, different user.

**Missing function-level authorization**
Attacker accesses admin endpoints that are not properly protected. Vertical privilege escalation — regular user accessing admin functions.

**JWT privilege escalation**
Attacker modifies the role or permissions claim in a JWT and forges a valid signature using algorithm confusion or alg:none. Claims admin role without authorization.

**SSRF to cloud metadata**
On cloud platforms, attacker uses SSRF to reach the instance metadata service and retrieve IAM credentials with elevated permissions. Used in the Capital One breach.

**Insecure sudo / SUID binaries**
On Linux systems, world-writable SUID binaries or overly permissive sudo rules allow low-privilege processes to execute commands as root.

**Container escape**
Misconfigured Docker containers running as root, with excessive capabilities, or with the Docker socket mounted allow attackers to escape the container and access the host system.

**OAuth scope abuse**
Attacker tricks a user into granting broader OAuth scopes than necessary. Uses those scopes to access resources beyond the intended integration.

### Real World Examples

**Facebook 2018 — Access Token Theft**
A bug in the "View As" feature allowed attackers to steal access tokens of other users. The vulnerability combined three separate bugs — a video uploader bug, a wrong permission check, and tokens generated for the wrong user. 50 million accounts affected.
Cost: $5 billion FTC fine (largest ever at the time for a tech company), €1.2 million GDPR fine in Ireland.

**Coinbase 2021 — IDOR in Trading API**
A security researcher discovered that Coinbase's trading API did not properly verify that orders belonged to the authenticated user. An attacker could cancel or modify any other user's open orders by guessing order IDs.
Reported through bug bounty — no public exploitation confirmed.

**Tesla 2020 — Kubernetes RBAC Misconfiguration**
RedLock researchers found that Tesla's Kubernetes admin console was exposed without password protection. Attackers had used it to deploy cryptomining malware. The compromise went undetected because the malicious pods mimicked legitimate workloads.
Cost: Significant cryptocurrency mining costs, security investigation overhead.

### Code Examples

**Vulnerable — no role check on admin endpoint:**
```javascript
app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
```

**Secure — enforce role-based access:**
```javascript
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user.roles.includes(role)) {
            auditLog.warn('unauthorized_access_attempt', { userId: req.user.id, endpoint: req.path });
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}
app.delete('/api/admin/users/:id', authenticate, requireRole('admin'), async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
```

**Vulnerable — container running as root:**
```dockerfile
FROM node:18
COPY . .
RUN npm install
CMD ["node", "server.js"]
# Runs as root — container escape gives root on host
```

**Secure — non-root user in container:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
CMD ["node", "server.js"]
```

**Vulnerable — excessive IAM permissions:**
```json
{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
}
```

**Secure — least privilege IAM:**
```json
{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::my-app-uploads/*"
}
```

### Kill Chain Stages
Elevation of privilege typically enables: Privilege Escalation → Persistence → Lateral Movement → Exfiltration → Impact

### MITRE ATT&CK Mappings
- T1548 Abuse Elevation Control Mechanism
- T1134 Access Token Manipulation
- T1078 Valid Accounts
- T1611 Escape to Host
- T1068 Exploitation for Privilege Escalation

### Mitigations
- Implement RBAC with deny-by-default — require explicit permission grants
- Apply object-level authorization on every API endpoint scoped to the authenticated user
- Run containers as non-root with read-only filesystem where possible
- Apply IAM least privilege — grant only the specific actions and resources needed
- Enforce IMDSv2 to prevent SSRF-based credential theft
- Audit privileged endpoints regularly for missing authorization checks
- Use Kubernetes RBAC and network policies to isolate workloads
- Log all authorization failures and alert on repeated violations

---

## STRIDE Quick Reference

| Category | Attacker Goal | Key Controls | MITRE Tactic |
|---|---|---|---|
| Spoofing | Impersonate a user or service | MFA, HttpOnly cookies, JWT algorithm enforcement | Initial Access |
| Tampering | Modify data or code | Parameterized queries, input validation, code signing | Execution |
| Repudiation | Deny an action occurred | Audit logging, append-only logs, digital signatures | Defense Evasion |
| Information Disclosure | Read unauthorized data | Encryption, RBAC, generic error messages | Exfiltration |
| Denial of Service | Make service unavailable | Rate limiting, DDoS protection, input validation | Impact |
| Elevation of Privilege | Gain higher permissions | RBAC, least privilege, container hardening | Privilege Escalation |
