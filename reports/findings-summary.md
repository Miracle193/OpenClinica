# Summary of Findings
## Summary

| ID | Title                          | Severity | Status |
|----|--------------------------------|----------|--------|
| 1  | Path Traversal in File Upload | High     | Open   |
| 2 | XML External Entities (XXE) in File Upload | High     | Open   |

## Path Traversal in File Upload (CWE-22)
Location: `web/src/main/java/org/akaza/openclinica/controller/openrosa/OpenRosaSubmissionController.java`
Method: `processUploadFile()`
Line: ~110
Severity: High

### Description
The application constructs a file path using a user-controlled filename obtained from a multipart file upload:
```java
String fileName = item.getName();
File uploadedFile = new File(dirToSaveUploadedFileIn + File.separator + fileName);
```
The `fileName` is not properly sanitized before being used in path construction. While the application performs canonical path validation for the base directory (`studyOID`), it does not validate or normalize the uploaded file name itself.

This allows an attacker to supply crafted file names containing directory traversal sequences (e.g., `../`), potentially escaping the intended upload directory.

### Impact
- Arbitrary file write outside intended directory
- Potential overwrite of sensitive files
- Possible Remote Code Execution (RCE) if files are written to executable locations (e.g., web root)

### Proof of Concept (PoC)
Upload a file with a malicious filename such as:

`../../../../tmp/evil.txt`

If not properly handled, the resulting file path may resolve outside the intended upload directory:

`/safe/upload/dir/../../../../tmp/evil.txt`

### Existing Mitigation (Partial)

The method `getAttachedFilePath()` validates the studyOID using canonical path checks:

`if (canonicalPath.startsWith(attachedFilePath))`

However, this protection does not extend to the uploaded filename, leaving a gap in security.

### Recommended Fix
1. Normalize filename
```java
fileName = Paths.get(fileName).getFileName().toString();
```

2. Validate filename (allowlist)
```java
if (!fileName.matches(["a-zA-Z0-9._-]+")) {
    throw new SecurityException("Invalid file name");
}
```

3. Enforce canonical path check after combining
```java
File file = new File(dirToSaveUploadedFileIn, fileName);

String basePath = new File(dirToSaveUploadedFileIn).getCanonicalPath();
String filePath = file.getCanonicalPath();

if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Path traversal attempt");
}
```

4. (Best Practice) Generate server-side filenames
```java
String safeName = UUUID.randomUUID().toString();
```

## XML External Entities (XXE) in File Upload (CWE-611)
Location: `web/src/main/java/org/akaza/openclinica/controller/openrosa/OpenRosaSubmissionController.java`
Method: `parseDocument(File f)`
Line: ~50
Severity: High

### Description
The application uses `SAXParserFactory` to parse XML input without disabling external entity processing:

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser sp = spf.newSAXParser();
sp.parse(f, this);
```
By default, the parser allows processing of external entities and DTDs. If untrusted XML input is parsed, this can lead to XML External Entity (XXE) attacks.

### Impact
- Disclosure of sensitive files (e.g., /etc/passwd)
- Server-Side Request Forgery (SSRF)
- Denial of Service (e.g., Billion Laughs attack)

### Proof of Concept (PoC)
Malicious XML payload:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rule>
  <name>&xxe;</name>
</rule>
```
If processed, the parser may include contents of local files in application data.

### Existing Mitigation (Partial)
None observed. The parser is created with default insecure settings.

### Recommended Fix
Disable external entities and DTD processing:

```java
SAXParserFactory spf = SAXParserFactory.newInstance();

spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

spf.setXIncludeAware(false);
spf.setNamespaceAware(true);
```

4. (Best Practice) Generate server-side filenames
```java
String safeName = UUUID.randomUUID().toString();
```

### References
- CWE-22: Path Traversal
- OWASP Top 10: A05 – Security Misconfiguration / A01 – Broken Access Control
- CWE-611: Improper Restriction of XML External Entity Reference