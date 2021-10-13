Dashboard API
===

Domain: http://dashboard.fdo.tools

Path: /logger/100/msg/

Protocol version: 100

The transport requirements and all error definitions are described in the FDO specs.

All commands require proper content-type, and authorization header containing previously issued by the dashboard access token.

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



