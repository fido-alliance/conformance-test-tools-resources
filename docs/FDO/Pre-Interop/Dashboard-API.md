Dashboard API
===

Domain: http://dashboard.fdo.tools
HTTP Only domain: http://http.dashboard.fdo.tools

Path: /logger/101/msg/

Protocol version: 101

The transport requirements and all error definitions are described in the FDO specs.

## Authorization and Header

- Required header Content-Type set to "application/cbor"
- Required header Authorization set to the issued by FIDO Alliance authorization token

## Commands

### SubmitEvent, Type 10

The event party sends an event with the GUID of the device in question, and the protocol that was utilized.

*CDDL**
```yaml
LoggerEvent = [
    Guid: bstr,
    TOProtocol: uint,
    Nonce: bstr // NonceTO0Sign or NonceTO1Proof or NonceTO2SetupDv 
]

toprotocols = (
  TO0: 0,
  TO1: 1,
  TO2: 2
)
```

On success the server will response with OK(200), or in case of error with other status code and corresponding FDOError.



