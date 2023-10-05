FIDO Alliance Pre-Interop Requirements
===

The interop will be implemented as a match making competition with all parties reporting results to the referee dashboard.

There are three groups involved: Devices, RV(Rendezvous)s and DO(Device Onboarding)s. For each of the member of the group, an access token is issued that is used to notify the dashboard that enrollment was successfully finished.

The device and DO token will be given to DO. The DO will use it's own, DO token to report back to the dashboard it's own state. During the serviceInfo exchange the DO will pass device token as a ServiceInfo and device will use that to connect to the dashboard and report success of the enrollment.


The idea is that to succeed all entities need to show successful interaction with each other, and report it back to the dashboard. 

![FIDO FDO Matchmaking](https://github.com/fido-alliance/conformance-test-tools-resources/blob/4360a9d653f743b4f06c5bbdb52983956cdfd1cb/docs/FDO/Pre-Interop/FDO%20FIDO%20Alliance.png)

## Dashboard API

The dashboard API can be found in [API reference](./Dashboard-API.md)

## URLs

- Rendezvous Server https://rv.fdo.tools
  + HTTP ONLY http://http.rv.fdo.tools
- Dashboard https://dashboard.fdo.tools
  + HTTP ONLY http://http.dashboard.fdo.tools

## Minimum requirements

- Support HMAC/HASH: SHA256/SHA384
- Support KEX: ECDH
- Supporting PublicKey: X509 and COSE public key encoding
- Supporting Signature: ES256/ES384
- Supporting Encryption: AES128/CTR/HMAC-SHA256
- Supporting FIDO Conformance API and ServiceInfo extension.

## Voucher encoding format

PEM encoded voucher with PKIX/PKCS7 NON-ENCRYPTED private key

Example:

```
-----BEGIN OWNERSHIP VOUCHER-----
hIYYZFCQcbE4QPtOxp2F6ODCcIRigYGCBWlsb2NhbGhvc3R4JEkgYW0gYSBwb3Rh
dG9lISBTbWFydCwgSW9ULCBwb3RhdG9lIYMmAVhbMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEYaVUiFrVMEWHUks0sCLKnsPfsvqrFvqROxQW5zyntlugM2qM0QcI
VdkfdexCqRw/+snm5duDd6iNJRLScu84goIY8Fgg8IEXOvmNiRBZhp2br0321lgm
N+QfCv/PcGYG05P4KNyCBVggpgMTpuZ5ONLm55++LSqyVz04kitnnkuG40X+aOiw
m8KCWQJWMIICUjCCAfmgAwIBAgIRALk/AFCNMUyeq/Kk/b2fIXcwCgYIKoZIzj0E
AwIwgYExLjAsBgNVBAMMJUZBS0UgQ09ORk9STUFOQ0UgRkRPIERFVklDRSBST09U
IEZBS0UxHDAaBgNVBAoME0ZJRE8gQWxsaWFuY2UsIEluYy4xJDAiBgNVBAsMG0Nl
cnRpZmljYXRpb24gV29ya2luZyBHcm91cDELMAkGA1UEBhMCVVMwIBcNMjEwOTMw
MTQxMzU4WhgPMjA1MTA5MzAxNDEzNThaMIGcMQswCQYDVQQGEwJVUzEbMBkGA1UE
ChMSRklETyBBbGxpYW5jZSwgSW5jMSQwIgYDVQQLExtDZXJ0aWZpY2F0aW9uIFdv
cmtpbmcgR3JvdXAxSjBIBgNVBAMTQUZBS0UgQ09ORk9STUFOQ0UgRkRPIERFVklD
RSA5MDcxQjEzODQwRkI0RUM2OUQ4NUU4RTBDMjcwODQ2MiBGQUtFMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEyVnd1+pTz1wLS/QtDrDGZujgrInwS+RCNis5/ydS
JjsBw052p0dChlrABBfwn6hQXgybBSi3LDl+9FHSwubgd6MzMDEwDgYDVR0PAQH/
BAQDAgeAMB8GA1UdIwQYMBaAFOLyglbZWKpRZHwsqEO8/mky4KRpMAoGCCqGSM49
BAMCA0cAMEQCIFonjkeDP99C1/gzyELujIPJNMpkxBwB4tGHGQkGz/g/AiBe6700
EEkQlUqU/hrsQWC771mLaAhGickBrWd22ypb81kCbzCCAmswggIRoAMCAQICFFqx
fIt5CnslHQpjGFyf8HqeW6nKMAoGCCqGSM49BAMCMIGBMS4wLAYDVQQDDCVGQUtF
IENPTkZPUk1BTkNFIEZETyBERVZJQ0UgUk9PVCBGQUtFMRwwGgYDVQQKDBNGSURP
IEFsbGlhbmNlLCBJbmMuMSQwIgYDVQQLDBtDZXJ0aWZpY2F0aW9uIFdvcmtpbmcg
R3JvdXAxCzAJBgNVBAYTAlVTMCAXDTIxMDkzMDE0MDczNFoYDzIwNzYwNzAzMTQw
NzM0WjCBgTEuMCwGA1UEAwwlRkFLRSBDT05GT1JNQU5DRSBGRE8gREVWSUNFIFJP
T1QgRkFLRTEcMBoGA1UECgwTRklETyBBbGxpYW5jZSwgSW5jLjEkMCIGA1UECwwb
Q2VydGlmaWNhdGlvbiBXb3JraW5nIEdyb3VwMQswCQYDVQQGEwJVUzBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABDJILDMLR+lFk9yAZxxlRBqVj/ONOT9WwnkhGzxf
91C+kwjlFKRm5VWbhExsv+8hhf30hviPBflktB4isqRSC7ujYzBhMA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMB0GA1UdDgQWBBTi8oJW2ViqUWR8LKhD
vP5pMuCkaTAfBgNVHSMEGDAWgBTi8oJW2ViqUWR8LKhDvP5pMuCkaTAKBggqhkjO
PQQDAgNIADBFAiEAlqlnDLNXonRAnK2e887S7ru0T+t1JCPu4H4arLdvaw0CIEzo
9aWxwdo4x6TvCWbHt38+8/Cr9UEnNGnQmFxMZERdgYRDoQEmoToBDwG9gwAA9lir
g4IY8FggGmFM9LBPWEgR6TsoOyHoY+B3NahwK2L1sgj7mxkJWfSCGPBYIKWNZSkF
AHspJIbwjGC5vBiLtIBjyjH581Yk9iWn+RXNgyYBWFswWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASO9z2iEipllKU0Ut7co6/NvtTMRV0Vw1/ri4pCtDFJnnZAtaAL
GmFa9Y2NJHFFOWVZO1+0rQzCqEJ5lidbBJP/WEABx8HvhAbjP2eofXMl8K2p0zbs
OHxlZayfXdriLTHH2bHlm91oDp7As1/dhWFVk86kRYebD+uL3n1Ych2kD86G
-----END OWNERSHIP VOUCHER-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIMzWgQJ3kiyABcruPwg7XCrJyhwmkBLChXUCSqo+KIKoAoGCCqGSM49
AwEHoUQDQgAEjvc9ohIqZZSlNFLe3KOvzb7UzEVdFcNf64uKQrQxSZ52QLWgCxph
WvWNjSRxRTllWTtftK0MwqhCeZYnWwST/w==
-----END EC PRIVATE KEY-----
```

## Conformance Service Info

For the FDO interop the service info extension is idenfied as 

```
fido_alliance:dev_conformance
```

With the value of type String that contains an access token.

