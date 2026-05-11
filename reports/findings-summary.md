# Summary of Findings
## Summary

| ID | Title                          | Severity | Status | Source |
|----|--------------------------------|----------|--------|--------|
| 1  | Path Traversal in File Upload | High     | Open   | Semgrep  |
| 2 | XML External Entities (XXE) in File Upload | High     | Open   | Semgrep |
| 3 | Multiple vulnerabilites in PostgreSQL version | Critical    | Open   | OWASP Dependency Check |
| 4 | Multiple vulnerabilites in prototype.js version | High   | Open   | OWASP Dependency Check |
| 5 | DoS vulnerability | High   | Open   | OWASP Dependency Check |

## #1 Path Traversal in File Upload (CWE-22)
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

## #2 XML External Entities (XXE) in File Upload (CWE-611)
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
By default, the parser allows processing of external entities and [DTDs](https://www.w3schools.com/xml/xml_dtd.asp). If untrusted XML input is parsed, this can lead to XML External Entity (XXE) attacks.

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
// Create a new SAX parser factory instance
SAXParserFactory spf = SAXParserFactory.newInstance();


// Completely disallow DOCTYPE declarations
// Prevents attackers from defining DTDs in XML input
// This is one of the strongest XXE protections
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);


// Disable external general entities
// Prevents XML from loading external resources like files or URLs
// Blocks attacks such as reading /etc/passwd
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);


// Disable external parameter entities
// Prevents attackers from using parameter entities in DTDs
// Important because some XXE payloads rely on parameter entities
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);


// Prevent loading external DTD files
// Stops parser from fetching remote or local DTD resources
// Helps prevent SSRF and information disclosure
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);


// Disable XInclude processing
// Prevents XML documents from including other files/documents
// Another possible file inclusion attack vector
spf.setXIncludeAware(false);


// Enable XML namespace awareness
// Allows parser to correctly understand XML namespaces
// Not directly security-related, but recommended for proper XML handling
spf.setNamespaceAware(true);
```

## 3 - Multiple vulnerabilites in PostgreSQL version

### Dependency
web/src/main/config/libraries/postgresql-8.1-405.jdbc3.jar

### CVE
- CVE-2015-0244
- CVE-2015-3166
- CVE-2019-10211
- CVE-2018-1115 

### Severity
Critical

### Description
Multiple critical vulnerabilities were identified in the PostgreSQL dependency affecting older versions used by the application. These vulnerabilities include SQL injection, system error handling flaws, access control flaws, denial of service that could allow attackers to compromise database confidentiality, integrity, and availability.

### Risk to OpenClinica
Because OpenClinica stores sensitive clinical trial and healthcare data, exploitation of these vulnerabilities could result in unauthorized data access, data manipulation, or service disruption.

### Remediation
Upgrade PostgreSQL to a patched and supported version newer than:
- 10.4

Additionally:
- Validate and sanitize database inputs
- Use parameterized queries
- Restrict database network exposure
- Regularly patch dependencies and database software

## 4 - Multiple vulnerabilites in prototype.js version

### Dependency
web/src/main/webapp/includes/prototype.js

### CVE
- CVE-2020-27511
- CVE-2008-7220 

### Severity
High

### Description
Multiple high vulnerabilities were identified in the prototype.js dependency affecting older versions used by the application. These vulnerabilities include Denial of Service (DoS), Cross-Origin Resource Sharing (CORS) that could allow attackers to compromise database confidentiality, integrity, and availability.

### Risk to OpenClinica
Because OpenClinica stores sensitive clinical trial and healthcare data, exploitation of these vulnerabilities could result in unauthorized data access or service disruption.

### Remediation
Upgrade prototype.js to a patched and supported version newer than:
- 1.7.3

## 5 - DoS vulnerability

### Dependency
web/src/main/webapp/includes/ua-parser.min.js

### CVE
- CVE-2020-7733

### Severity
High

### Description
Denial of Service (DoS) vulnerability was identified in the prototype.js dependency affecting older versions of 0.7.22.

### Risk to OpenClinica
Because OpenClinica stores sensitive clinical trial and healthcare data, exploitation of these vulnerabilities could result in service disruption.

### Remediation
Upgrade ua-parser.min.js to a patched and supported version newer than:
- 0.7.22

## Git Leaks Scan Results
No hardcoded secrets were detected in the OpenClinica codebase, indicating strong baseline credential hygiene.

## References
- CWE-22: Path Traversal
- OWASP Top 10: A05 – Security Misconfiguration / A01 – Broken Access Control
- CWE-611: Improper Restriction of XML External Entity Reference