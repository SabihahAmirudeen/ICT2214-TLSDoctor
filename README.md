# ICT2214-TLSDoctor

Targetting C04-Cryptographic Failure

- Used a baseline project from github that is open source TLS/SSL scanner
- Bash script (Linux-based)
- Uses OpenSSL + system tools
- Performs server-side TLS security analysis

it detects whether the server supports TLS 1.2/1.3
it chesks for:
- Certificate validity dates
- Expired certificates
- Self-signed certificates
- Weak ciphers
- TLS Vulnerabilities like HeartBleed, POODLE

It doesnt cheeck:
- mixed content,
- subresource integrity (SRI)
- cookie flags
- CSP/Security headers
- authentication exposure logic etc

testssl.sh provides low-level TLS protocol and cryptographic configuration analysis. However, it does not evaluate application-layer enforcement, session security, browser-side integrity, or compound misconfigurations. TLSDoctor extends this baseline by correlating transport-layer findings with application-layer and browser-integrity checks to provide holistic cryptographic hygiene assessment.

Features: 
authentication transport check
cert_check
cookies
redirect hsts
sri_check
mixed content
risk scoring + reporting

Further work:
- certificate strength and signature validation check
Specifically check:
    Key size
    Signature algorithm
    Expiry window (<30 days)
    Self-signed detection
    Missing revocation endpoints
All using Python’s ssl + socket