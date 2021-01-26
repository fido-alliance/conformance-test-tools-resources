# Running FIDO2 Server tests

## FIDO2 Server Tests Options

1. MakeCredential Request
2. MakeCredential Response
3. GetAssertion Request
4. GetAssertion Response
5. Metadata Service Tests

You can choose these options what you want to test.

<img src="1.png" width="50%"/>

## Preparations and Configurations

* Setup your FIDO2 server with HTTPS enable access.
* Click "DOWNLOAD SERVER METADATA" to download metadata and register metadata to your server.
* Register your server url at https://fidoalliance.co.nz/mds/ and add provided MDS endpoints to your server.
* Then you can find 5 url for MDS. Setup those 5 urls to access from your server.
* Launch FIDO Conformance Tools and set your server url into text box at TESTS CONFIGURATION.

<img src="2.png" width="50%"/>

* If you want to capture network while testing, launch inspector tool from Menu -> Open Inspector menu.

<img src="3.png" width="50%"/>

* Check the options you want to test.

<img src="4.png" width="50%"/>

## Run tests

* After you complete preparations and configurations, just click a green "RUN" button.

<img src="5.png" width="50%"/>


## Test Results
* You can see the results of tests on top of the tool's screen.

<img src="6.png" width="80%"/>

* If you don't find any number of failure, you can see the RED "SUBMIT RESULT" button on bottom of application screen.

<img src="7.png" width="50%"/>


## Submit Results

* Click RED "SUBMIT RESULT" button to submit result to FIDO alliance.
* You need to run 5 test cases at once to submit successful results. If you run 5 test cases separately, you cannot see red "SUBMIT RESULT" button even if your server passes all test items.


## Test Items

* Bellow lists describes mandatory test items.(some of lists are optional.)
* The "P" in the number like "P-n" means the server should return correct  successful response.
* The "F" in the number like "F-n" means the server should return correct error response.

### "MakeCredential Request" test items

#### Server-ServerPublicKeyCredentialCreationOptions-Req-1
##### Test server generating ServerPublicKeyCredentialCreationOptionsRequest

* P-1 Get ServerPublicKeyCredentialCreationOptionsResponse, and check that: (a) response MUST contain "status" field, and it MUST be of type DOMString and set to "ok" (b) response MUST contain "errorMessage" field, and it MUST be of type DOMString and set to an empty string (c) response contains "user" field, of type Object and: (1) check that user.name is not missing, and is of type DOMString (2) check that user.displayName is not missing, and is of type DOMString (3) check that user.id is not missing, and is of type DOMString, and is not empty. It MUST be base64url encoded byte sequence, and is not longer than 64 bytes. (4) If user.icon is presented, check that it's is of type DOMString (d) response contains "rp" field, of type Object and: (1) check that rp.name is not missing, and is of type DOMString (2) check that rp.id is not missing, and is of type DOMString. (3) If rp.icon is presented, check that it's is of type DOMString (e) response contains "challenge" field, of type String, base64url encoded and not less than 16 bytes. (f) response contains "pubKeyCredParams" field, of type Array and: (1) each member MUST be of type Object (2) each member MUST contain "type" field of type DOMString (3) each member MUST contain "alg" field of type Number (4) MUST contain one member with type set to "public-key" and alg set to an algorithm that is supported by the authenticator (g) If response contains "timeout" field, check that it's of type Number and is bigger than 0 (h) response contains "extensions" field, with "example.extension" key presented‣
* P-2 Request from server ServerPublicKeyCredentialCreationOptionsResponse with "none" attestation, and check that server, and check that ServerPublicKeyCredentialCreationOptionsResponse.attestation is set to "none"‣
* P-3 Get two ServerPublicKeyCredentialCreationOptionsResponses, and check that challenge in Request1 is different to challenge in Request2

### "MakeCredential Response" test items
#### Server-ServerAuthenticatorAttestationResponse-Resp-1 
##### Test server processing ServerAuthenticatorAttestationResponse structure

* P-1 Get PublicKeyCredentialCreationOptions, generate a valid response(with for example packed attestation). Get another one of PublicKeyCredentialCreationOptions for the same username as in previous request, and check that it's have "excludeCredentials" field and: (a) it's of type Array (b) it's not empty (c) each member is of type PublicKeyCredentialDescriptor (d) it contains PublicKeyCredentialDescriptor, with "type" set to "public-key", and "id" set to base64url encoded credId from the previous registration
* F-1 Send ServerAuthenticatorAttestationResponse that is missing "id" field and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with "id" field is NOT of type DOMString, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with "id" is not base64url encode, and check that server returns an error
* F-4 Send ServerAuthenticatorAttestationResponse that is missing "type" field and check that server returns an error
* F-5 Send ServerAuthenticatorAttestationResponse with "type" field is NOT of type DOMString and check that server returns an error
* F-6 Send ServerAuthenticatorAttestationResponse with "type" is not set to "public-key", and check that server returns an error
* F-7 Send ServerAuthenticatorAttestationResponse that is missing "response" field and check that server returns an error
* F-8 Send ServerAuthenticatorAttestationResponse with "response" field is NOT of type Object and check that server returns an error
* F-9 Send ServerAuthenticatorAttestationResponse that is missing "response.clientDataJSON" and check that server returns an error
* F-10 Send ServerAuthenticatorAttestationResponse with response.clientDataJSON is not of type DOMString and check that server returns an error
* F-11 Send ServerAuthenticatorAttestationResponse with response.clientDataJSON is empty DOMString and check that server returns an error
* F-12 Send ServerAuthenticatorAttestationResponse that is missing response.attestationObject and check that server returns an error
* F-13 Send ServerAuthenticatorAttestationResponse with response.attestationObject is not of type DOMString and check that server returns an error
* F-14 Send ServerAuthenticatorAttestationResponse with response.attestationObject is empty DOMString and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-2
##### Test server processing CollectClientData

* F-1 Send ServerAuthenticatorAttestationResponse with clientDataJSON struct missing "type" field
* F-2 Send ServerAuthenticatorAttestationResponse with clientDataJSON.type is not of type DOMString
* F-3 Send ServerAuthenticatorAttestationResponse with clientDataJSON.type is empty DOMString
* F-4 Send ServerAuthenticatorAttestationResponse with clientDataJSON.type is not set to "webauthn.create"
* F-5 Send ServerAuthenticatorAttestationResponse with clientDataJSON.type is set to "webauthn.get"
* F-6 Send ServerAuthenticatorAttestationResponse with clientDataJSON struct missing "challenge" field
* F-7 Send ServerAuthenticatorAttestationResponse with clientDataJSON.challenge is not of type DOMString
* F-8 Send ServerAuthenticatorAttestationResponse with clientDataJSON.challenge is empty DOMString
* F-9 Send ServerAuthenticatorAttestationResponse with clientDataJSON.challenge is not base64url encoded
* F-10 Send ServerAuthenticatorAttestationResponse with clientDataJSON.challenge is not set to request.challenge
* F-11 Send ServerAuthenticatorAttestationResponse with clientDataJSON struct missing "origin" field
* F-12 Send ServerAuthenticatorAttestationResponse with clientDataJSON.origin is not of type DOMString
* F-13 Send ServerAuthenticatorAttestationResponse with clientDataJSON.origin is empty DOMString
* F-14 Send ServerAuthenticatorAttestationResponse with clientDataJSON.origin is not set to the origin
* F-15 Send ServerAuthenticatorAttestationResponse with clientDataJSON.tokenBinding is not of type Object
* F-16 Send ServerAuthenticatorAttestationResponse with clientDataJSON.tokenBinding missing status field
* F-17 Send ServerAuthenticatorAttestationResponse with clientDataJSON.tokenBinding.status is not set to either of present, supported or not-supported

#### Server-ServerAuthenticatorAttestationResponse-Resp-3
##### Test server processing AttestationObject

* P-1 Send "packed" ServerAuthenticatorAttestationResponse with attestationObject.authData contains extension data, and ED is set to true, and check that server accepts the response
* F-1 Send ServerAuthenticatorAttestationResponse with attestationObject is not a valid CBOR MAP, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with attestationObject is missing "fmt" field, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with attestationObject.fmt field is not of type String, and check that server returns an error
* F-4 Send ServerAuthenticatorAttestationResponse with attestationObject is missing "attStmt" field, and check that server returns an error
* F-5 Send ServerAuthenticatorAttestationResponse with attestationObject.attStmt is not of type MAP, and check that server returns an error
* F-6 Send ServerAuthenticatorAttestationResponse with attestationObject is missing "authData" field, and check that server returns an error
* F-7 Send ServerAuthenticatorAttestationResponse with attestationObject.authData is not of type BYTE SEQUENCE, and check that server returns an error
* F-8 Send ServerAuthenticatorAttestationResponse with attestationObject.authData is an empty BYTE SEQUENCE, and check that server returns an error
* F-9 Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is not set, but Attestation Data is presented, and check that server returns an error
* F-10 Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is not set, and Attestation Data is not presented, and check that server returns an error
* F-11 Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is set, and Attestation Data is not presented, and check that server returns an error
* F-12 Send ServerAuthenticatorAttestationResponse with attestationObject.authData AttestationData contains leftover bytes, and check that server returns an error
* F-13 Send "packed" ServerAuthenticatorAttestationResponse with attStmt being an empty map, and check that server returns an error
* F-14 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg is missing, and check that server returns an error
* F-15 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg is not of type Number, and check that server returns an error
* F-16 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg does not match Alg in metadata statement, and check that server returns an error
* F-17 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig is missing, and check that server returns an error
* F-18 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig is not of type BYTE STRING, and check that server returns an error
* F-19 Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig set to empty BYTE STRING, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-4
##### Test server support of the authentication algorithms

* P-1 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW" algorithm, and check that server succeeds [AWAITS IANA]
* P-2 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA256_RAW" algorithm, and check that server succeeds
* P-3 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA384_RAW" algorithm, and check that server succeeds
* P-4 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA512_RAW" algorithm, and check that server succeeds
* P-5 Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW" algorithm, and check that server succeeds
* P-6 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW" algorithm, and check that server succeeds
* P-7 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW" algorithm, and check that server succeeds
* P-8 Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW" algorithm, and check that server succeeds
* P-9 Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW" algorithm, and check that server succeeds
* P-10 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW" algorithm, and check that server succeeds
* P-11 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW" algorithm, and check that server succeeds
* P-12 OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_ED25519_EDDSA_SHA512_RAW" algorithm, and check that server succeeds

#### Server-ServerAuthenticatorAttestationResponse-Resp-5
##### Test server processing "packed" FULL attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation, and check that server succeeds
* P-2 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation that contains chain that links to the root certificate in the metadata in it's response, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with fmt set to an unknown attestation format, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, and with attStmt.sig contains a signature that can not be verified, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt missing "x5c" field, and check that server returns an error
* F-4 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c is not of type ARRAY, and check that server returns an error
* F-5 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c is an empty ARRAY, and check that server returns an error
* F-6 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate that is expired, and check that server returns an error
* F-7 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate that is not yet started, and check that server returns an error
* F-8 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate algorithm does not equal to the one that is specified in MetadataStatement, and check that server returns an error
* F-9 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains certificate chain, that can not be verified, and check that server returns an error
* F-10 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c containing full chain, and check that server returns an error
* F-11 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c containing full chain, that is not correctly ordered, and check that server returns an error
* F-12 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains expired intermediate certificate, and check that server returns an error
* F-13 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with signature that can not be verified by the public key extracted from leaf certificate, and check that server returns an error
* F-14 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with signature that is generated using new credential private key, and not attestation batch private key, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-6
##### Test server processing "packed" SELF(SURROGATE) attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with SELF(SURROGATE) "packed" attestation, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with SELF "packed" attestation, and with attStmt.sig contains an invalid signature, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with SELF "packed" attestation, that contains full attestation, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with SELF "packed" attestation, with fmt set to an unknown attestation format, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-7
##### Test server processing "none" attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with SELF(SURROGATE) "packed" attestation, and check that server succeeds
* P-2 Send a valid ServerAuthenticatorAttestationResponse with SELF(SURROGATE) "packed" attestation, and check that server succeeds
* F-1 For server that expects attestation "none", send attestation FULL packed, with fmt set "none" and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-8
##### Test server processing "fido-u2f" attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with "fido-u2f" attestation, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with "fido-u2f" attestation, authData.AAGUID is not 0x00, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with "fido-u2f" attestation, and with attStmt.sig contains an invalid signature, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-9
##### Test server processing "tpm" attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation for SHA-256, and check that server succeeds
* P-2 Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation for SHA-1, and check that server succeeds
* P-3 Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation pubArea.nameAlg is not matching algorithm used for generate attested.name, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with "tpm" attestation has incorrect certificate order, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with "tpm" attestation certInfo.extraData is not set to a valid hash of attToBeSigned, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with "tpm" attestation certInfo.magic is not set to TPM_GENERATED_VALUE(0xff544347), and check that server returns an error
* F-4 Send ServerAuthenticatorAttestationResponse with "tpm" attestation pubArea.unique is not set to newly generated public key, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-A
##### Test server processing "android-key" attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with "android-key" attestation, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with "android-key" attestation leaf certificate contains an invalid clientDataHash, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with "android-key" attestation leaf certificate contains an invalid public key, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with "android-key" attestation incorrect certificate order, and check that server returns an error

#### Server-ServerAuthenticatorAttestationResponse-Resp-B
##### Test server processing "android-safetynet" attestation

* P-1 Send a valid ServerAuthenticatorAttestationResponse with "android-safetynet" attestation, and check that server succeeds
* F-1 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "ver" field is empty, and check that server returns an error
* F-2 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "response" field is empty, and check that server returns an error
* F-3 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "nonce" does not contain a valid attToBeSigned, and check that server returns an error
* F-4 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "x5c" is empty, and check that server returns an error
* F-5 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "ctsProfileMatch" is false, and check that server returns an error
* F-6 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "timestampMs" is set to future, and check that server returns an error
* F-7 Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "timestampMs" is older than 1 minute, and check that server returns an error


### "GetAssertion Request" test items
#### Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1
##### Test server generating ServerPublicKeyCredentialGetOptionsResponse

* P-1 Get ServerPublicKeyCredentialGetOptionsResponse, and check that: (a) response MUST contain "status" field, and it MUST be of type DOMString and set to "ok" (b) response MUST contain "errorMessage" field, and it MUST be of type DOMString and set to an empty string (c) response MUST contains "challenge" field, of type String, base64url encoded and not less than 16 bytes. (d) response MUST contains "extensions" field, of type Object, with "example.extension" set to a test string. (d) If response contains "timeout" field, check that it's of type Number and is bigger than 0 (e) If response contains "rpId" field, it: (1) MUST be of type SVSString (2) MUST be HTTPS URL (3) MUST be either RP origin, or suffix of the origin (4) MUST include port if applies (f) response contains "allowCredentials" field, of type Array and: (1) each member MUST be of type Object (2) each member MUST contain "type" field of type DOMString (3) check that "id" field is not missing, and is of type DOMString, and is not empty. It MUST be base64url encoded byte sequence. (4) check that it's contain exactly one member, with type set to "public-key" and id is set to previously registered credID. (g) response.userVerification MUST be set to the requested "userVerification"
* P-2 Get two ServerPublicKeyCredentialGetOptionsResponse, and check that challenge in Request1 is different to challenge in Request2

### "GetAssertion Response" test items
#### Server-ServerAuthenticatorAssertionResponse-Resp-1
##### Test server processing ServerAuthenticatorAssertionResponse structure

* P-1 Send a valid ServerAuthenticatorAssertionResponse, and check that server succeeds
* F-1 Send ServerAuthenticatorAssertionResponse that is missing "id" field and check that server returns an error
* F-2 Send ServerAuthenticatorAssertionResponse with "id" field is NOT of type DOMString, and check that server returns an error
* F-3 Send ServerAuthenticatorAssertionResponse with "id" is not base64url encode, and check that server returns an error
* F-4 Send ServerAuthenticatorAssertionResponse that is missing "type" field and check that server returns an error
* F-5 Send ServerAuthenticatorAssertionResponse with "type" field is NOT of type DOMString and check that server returns an error
* F-6 Send ServerAuthenticatorAssertionResponse with "type" is not set to "public-key", and check that server returns an error
* F-7 Send ServerAuthenticatorAssertionResponse that is missing "response" field and check that server returns an error
* F-8 Send ServerAuthenticatorAssertionResponse with "response" field is NOT of type Object and check that server returns an error
* F-9 Send ServerAuthenticatorAssertionResponse that is missing "response.clientDataJSON" and check that server returns an error
* F-10 Send ServerAuthenticatorAssertionResponse with response.clientDataJSON is not of type DOMString and check that server returns an error
* F-11 Send ServerAuthenticatorAssertionResponse with response.clientDataJSON is empty DOMString and check that server returns an error
* F-12 Send ServerAuthenticatorAssertionResponse that is missing response.authenticatorData and check that server returns an error
* F-13 Send ServerAuthenticatorAssertionResponse with response.authenticatorData is not of type DOMString and check that server returns an error
* F-14 Send ServerAuthenticatorAssertionResponse with response.authenticatorData is not base64url encoded and check that server returns an error
* F-15 Send ServerAuthenticatorAssertionResponse with response.authenticatorData is empty DOMString and check that server returns an error
* F-16 Send ServerAuthenticatorAssertionResponse that is missing response.signature and check that server returns an error
* F-17 Send ServerAuthenticatorAssertionResponse with response.signature is not of type DOMString and check that server returns an error
* F-18 Send ServerAuthenticatorAssertionResponse with response.signature is not base64url encoded and check that server returns an error
* F-19 Send ServerAuthenticatorAssertionResponse with response.signature is empty DOMString and check that server returns an error
* F-20 Send ServerAuthenticatorAssertionResponse with response.signature containing unverifiable signature
* F-21 Send ServerAuthenticatorAssertionResponse with response.userHandle is not of type DOMString and check that server returns an error

#### Server-ServerAuthenticatorAssertionResponse-Resp-2
##### Test server processing CollectClientData

* F-1 Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "type" field
* F-2 Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is not of type DOMString
* F-3 Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is empty DOMString
* F-4 Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is not set to "webauthn.get"
* F-5 Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is set to "webauthn.create"
* F-6 Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "challenge" field
* F-7 Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not of type DOMString
* F-8 Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is empty DOMString
* F-9 Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not base64url encoded
* F-10 Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not set to request.challenge
* F-11 Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "origin" field
* F-12 Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is not of type DOMString
* F-13 Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is empty DOMString
* F-14 Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is not set to the origin
* F-15 Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding is not of type Object
* F-16 Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding missing status field
* F-17 Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding.status is not set to either of present, supported or not-supported

#### Server-ServerAuthenticatorAssertionResponse-Resp-3
##### Test server processing authenticatorData

* P-1 Send a valid ServerAuthenticatorAssertionResponse, for the authenticator that does not support counter(counter is always 0), and check that server succeeds
* P-2 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UV is set, for userVerification set to "required", and check that server succeeds
* P-3 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP is set, for userVerification set to "required", and check that server succeeds
* P-4 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "preferred", and check that server succeeds
* P-5 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UP is set, despite requested userVerification set to "discouraged", and check that server succeeds
* P-6 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UV is set, despite requested userVerification set to "discouraged", and check that server succeeds
* P-7 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds
* P-8 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData contains extension data, and ED is set to true, and check that server accepts the response
* F-1 Send ServerAuthenticatorAssertionResponse with authenticatorData contains leftover bytes, and check that server returns an error
* F-2 Send ServerAuthenticatorAssertionResponse with authenticatorData.rpIdHash contains an invalid hash, and check that server returns an error
* F-3 Send ServerAuthenticatorAssertionResponse with authenticatorData.clientDataHash contains an invalid hash, and check that server returns an error
* F-4 For authenticator that supports counter: Send ServerAuthenticatorAssertionResponse with authenticatorData.counter is not increased, and check that server returns an error
* F-5 Send a valid ServerAuthenticatorAssertionResponse with only authenticatorData.flags.UP is set, for userVerification set to "required", and check that server returns an error

### Metadata Service Tests
#### Server-ServerAuthenticatorAttestationResponse-Resp-1
##### Test server processing ServerAuthenticatorAttestationResponse structure

* P-1 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for a valid MDS metadata, and check that server succeeds
* F-1 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's hash can not be verified, and check that serve returns an error
* F-2 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's status is set to USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE or USER_KEY_PHYSICAL_COMPROMISE, and check that serve returns an error
* F-3 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's signature can not be verified, and check that serve returns an error
* F-4 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's certificate chain can not be verified, and check that serve returns an error
* F-5 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's metadata service intermediate certificate is revoked, and check that serve returns an error
* F-6 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's metadata service leaf certificate is revoked, and check that serve returns an error




...




