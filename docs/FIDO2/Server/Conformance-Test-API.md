# FIDO2: Conformance testing server API

FIDO Alliance Certification Conformance Test Tools require companies to implement a standardised API for the conformance testing purpose.

## Contents

* [Introduction](#introduction)
* [Common](#common)
    * [Definitions](#common-idl)
        * [ServerResponse](#serverresponse)
* [Registration](#registration)
    * [Overview](#registration-overview)
    * [Definitions](#registration-idl)
        * [ServerPublicKeyCredentialCreationOptionsRequest](#serverpublickeycredentialcreationoptionsrequest)
        * [ServerPublicKeyCredentialCreationOptionsResponse](#serverpublickeycredentialcreationoptionsresponse)
        * [ServerAuthenticatorAttestationResponse](#serverauthenticatorattestationresponse)
        * [ServerPublicKeyCredential](#serverpublickeycredential)
        * [ServerPublicKeyCredentialUserEntity](#serverpublickeycredentialuserentity)
        * [ServerPublicKeyCredentialDescriptor](#serverpublickeycredentialdescriptor)
* [Authentication](#authentication)
    * [Overview](#authentication-overview)
    * [Definitions](#authentication-idl)
        * [ServerPublicKeyCredentialGetOptionsRequest](#serverpublickeycredentialgetoptionsrequest)
        * [ServerPublicKeyCredentialGetOptionsResponse](#serverpublickeycredentialgetoptionsresponse)
        * [ServerAuthenticatorAssertionResponse](#serverauthenticatorassertionresponse)
* [Examples](#examples)
    * [Registration Examples](#registration-examples)
        * [Credential Creation Options](#registration-example-credential-creation-options)
        * [Authenticator Attestation Response](#registration-example-authenticator-attestation-response)
    * [Authentication Examples](#authentication-examples)
        * [Credential Get Options](#authentication-example-credential-get-options)
        * [Authenticator Assertion Response](#authentication-example-authenticator-assertion-response)



## Introduction

This document contains a non-normative, proposed REST API for FIDO2 servers. While this interface is not required for real-world application, it is used for the FIDO2 conformance test tools so that servers can receive and send messages in a standard way and allow for those messages to be validated by the conformance test tools.

As with the FIDO2 specifications, the interfaces described here are highly dependent on the [WebAuthn](https://w3c.github.io/webauthn/) specification. The nomenclature of this document follows that of WebAuthn and reuses the Interface Definition Language (IDL) for defining the messages that are sent to / from the server.

> **Note:** This API may contain intentional discrepancies in some parameters when compared to the WebAuthn specification. Please keep in mind that this API is implemented **exclusively** for the testing purposes.
>
> Once the testing has been concluded, it may be safely removed from the production build.


## Common

This section defines reusable components that are required across multiple parts of the specification.
### Common IDL

#### ServerResponse
```java
    dictionary ServerResponse {
        required Status     status;
        required DOMString  errorMessage = "";
    }
```

* `status`, of type **Status**  
  $~~~~~$ Describes the status of the response. Can be set to either **"ok"** or **"failed"**.

* `errorMessage`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ If `status` is set to **"failed"** this field MUST NOT be empty. Default set to empty string.



## Registration

This section includes a brief overview of the registration messages that are exchanged between a client and the server with IDL definitions of the messages.
> Note that registration is also referred to as "credential creation" due to the WebAuthn nomenclature.

### Registration Overview
The registration flow consists of two steps, involving four messages in total.  
  
First, the client (e.g., Conformance Tools) retrieves "Credential Creation Options", which involves the client sending a [`ServerPublicKeyCredentialCreationOptionsRequest`](#ServerPublicKeyCredentialCreationOptionsRequest) to the server, which replies with a [`ServerPublicKeyCredentialCreationOptionsResponse`](#ServerPublicKeyCredentialCreationOptionsResponse).

These options are intended to be used as the parameters with WebAuthn's [navigator.credentials.create()](https://www.w3.org/TR/webauthn/#sctn-credentialcreationoptions-extension), particularly the server-generated challenge, which mitigates Man-in-the-Middle (MITM) attacks.

Upon completion of `navigator.credentials.create()` the resulting dictionary is sent back to the server as a [`ServerPublicKeyCredential`](#ServerPublicKeyCredential) with `response` field populated by a [`ServerAuthenticatorAttestationResponse`](#ServerAuthenticatorAttestationResponse). 
> Note that the `ServerAuthenticatorAttestationResponse` extends the generic `ServerResponse`, defined in the Common section.  
> 
> The server will validate challenges, origins, signatures and the rest of the `ServerAuthenticatorAttestationResponse` fields according to the algorithm described in section 7.1 of the [Webauthn](https://w3c.github.io/webauthn/#sctn-registering-a-new-credential) specs, then replies with a `ServerResponse` message.


### Registration IDL

#### ServerPublicKeyCredentialCreationOptionsRequest
```java
    dictionary ServerPublicKeyCredentialCreationOptionsRequest {
        required DOMString                username;
        required DOMString                displayName;
        AuthenticatorSelectionCriteria    authenticatorSelection;
        AttestationConveyancePreference   attestation = "none";
    };
```

* `username`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)\
  $~~~~~$ A human-readable name for the entity. For example, "alexm", "alex.p.mueller@example.com" or "+14255551234".

* `displayName`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)\
  $~~~~~$ A human-friendly name for the user account, intended only for display. For example, "Alex P. Müller" or "田中 倫".

* `authenticatorSelection`, of type [AuthenticatorSelectionCriteria](https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria)\
  $~~~~~$ A dictionary containing AuthenticatorSelectionCriteria described in [WebAuthn](https://w3c.github.io/webauthn/#authenticatorSelection) specification.

* `attestation`, of type [AttestationConveyancePreference](https://w3c.github.io/webauthn/#enum-attestation-convey) \
  $~~~~~$ Can be set to "none", "indirect", "direct". More in [WebAuthn](https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference) specification. Default set to none.

#### ServerPublicKeyCredentialCreationOptionsResponse
```java
    dictionary ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse {
        required PublicKeyCredentialRpEntity               rp;
        required ServerPublicKeyCredentialUserEntity       user;
        required DOMString                                 challenge;
        required sequence<PublicKeyCredentialParameters>   pubKeyCredParams;
        unsigned long                                      timeout;
        sequence<ServerPublicKeyCredentialDescriptor>      excludeCredentials = [];
        AuthenticatorSelectionCriteria                     authenticatorSelection;
        AttestationConveyancePreference                    attestation = "none";
        AuthenticationExtensionsClientInputs               extensions;
    };
```
* `rp`, of type [PublicKeyCredentialRpEntity](https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity)  
  $~~~~~$ The relying party entity described in WebAuthn specification.

* `user`, of type [ServerPublicKeyCredentialUserEntity](#ServerPublicKeyCredentialUserEntity)  
  $~~~~~$ The user entity described in this document.

* `challenge`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ A random base64url encoded challenge (minimum 16 bytes, maximum 64 bytes).

* `pubKeyCredParams`, of type sequence<[PublicKeyCredentialParameters](https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters)>  
  $~~~~~$ Supported public key credential parameters described in WebAuthn specification.

* `timeout`, of type [unsigned long](https://webidl.spec.whatwg.org/#idl-unsigned-long)  
  $~~~~~$ Operation timeout in milliseconds (optional).

* `excludeCredentials`, of type sequence<[ServerPublicKeyCredentialDescriptor](#ServerPublicKeyCredentialDescriptor)>  
  $~~~~~$ Credentials to exclude from creation. Default empty array.

* `authenticatorSelection`, of type [AuthenticatorSelectionCriteria](https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria)  
  $~~~~~$ Authenticator selection criteria described in WebAuthn specification.

* `attestation`, of type [AttestationConveyancePreference](https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference)  
  $~~~~~$ Can be "none", "indirect", or "direct". Default "none".

* `extensions`, of type [AuthenticationExtensionsClientInputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-inputs)  
  $~~~~~$ Authentication extensions described in WebAuthn specification.

#### ServerAuthenticatorAttestationResponse
Generally the same as [AuthenticatorAttestationResponse](https://w3c.github.io/webauthn/#authenticatorattestationresponse) from WebAuthn, but uses `base64url` encoding for fields that were of type `BufferSource`.

```java
dictionary ServerAuthenticatorAttestationResponse : ServerAuthenticatorResponse {
    required DOMString   clientDataJSON;
    required DOMString   attestationObject;
};
```

* `clientDataJSON`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url-encoded client data collected by the authenticator. Contains the challenge, origin, and other client information.

* `attestationObject`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url-encoded attestation data containing the public key, credential ID, and authenticator metadata.

#### ServerPublicKeyCredential
Generally the same as [PublicKeyCredential](https://w3c.github.io/webauthn/#publickeycredential) from WebAuthn, but uses `base64url` formatting for fields that are defined as `BufferSource` in WebAuthn.

```java
dictionary ServerPublicKeyCredential : Credential {
    required DOMString                      type;
    required DOMString                      id;
    required ServerAuthenticatorResponse    response;
    AuthenticationExtensionsClientOutputs   getClientExtensionResults;
};
```
* `id`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Inherited from Credential, overridden with base64url encoding of the authenticator credId by ServerPublicKeyCredential.

* `response`, of type **ServerAuthenticatorResponse**  
  $~~~~~$ Either [ServerAuthenticatorAttestationResponse](#ServerAuthenticatorAttestationResponse) or [ServerAuthenticatorAssertionResponse](#ServerAuthenticatorAssertionResponse) as described in this document.

* `type`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Inherited from Credential, though ServerPublicKeyCredential overrides it with **"public-key"**.

* `getClientExtensionResults`, of type [AuthenticationExtensionsClientOutputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-outputs)  
  $~~~~~$ A map of extension identifiers to their corresponding client extension output entries, generated during the client extension processing phase.

* Extends [Credential](https://w3c.github.io/webappsec-credential-management/#credential) described in Credential Management API specification



#### ServerPublicKeyCredentialUserEntity
Generally the same as the [PublicKeyCredentialUserEntity](https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity) from WebAuthn, but uses `base64url` formatting instead of `BufferSource` for `id`.

```java
    dictionary ServerPublicKeyCredentialUserEntity : PublicKeyCredentialEntity {
        required DOMString   id;
        required DOMString   displayName;
    };
```

* `id`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url encoded id buffer.

* `displayName`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ A human-friendly name for the user account, intended only for display. For example, "Alex P. Müller" or "田中 倫". Corresponding to ServerPublicKeyCredentialCreationOptionsRequest.displayName.

* Extends [PublicKeyCredentialEntity](https://w3c.github.io/webauthn/#dictdef-publickeycredentialentity) described in WebAuthn specification

#### ServerPublicKeyCredentialDescriptor
Generally the same as [PublicKeyCredentialDescriptor](https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor) from WebAuthn, but uses `base64url` formatting instead of `BufferSource` for `id`.

```java
    dictionary ServerPublicKeyCredentialDescriptor {
        required PublicKeyCredentialType   type;
        required DOMString                 id;
        sequence<AuthenticatorTransport>   transports;
    };
```
* `type`, of type [PublicKeyCredentialType](https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype)  
  $~~~~~$ A dictionary defined as [PublicKeyCredentialType](https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype) described in WebAuthn specification

* `id`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Contains base64url encoded credential ID of the public key credential that the caller is referring to

* `transports`, of type sequence<[AuthenticatorTransport](https://w3c.github.io/webauthn/#enum-transport)>  
  $~~~~~$ A sequence of [AuthenticatorTransport](https://w3c.github.io/webauthn/#enum-transport) described in WebAuthn specification

## Authentication

This section starts with an overview of the messages exchanged with the server for authentication with the specific IDL definitions of those messages. 
> Note that "authentication" is sometimes referred to as "getting credentials", a "credential request", or "getting an authentication assertion" due to the terminology used in WebAuthn.

### Authentication Overview

Similar to Registration, the Authentication flow requires four messages to be exchanged with the server.  

The first pair of messages are a request from the client to the server in the format of [`ServerPublicKeyCredentialGetOptionsRequest`](#ServerPublicKeyCredentialGetOptionsRequest) and the server replies with a [`ServerPublicKeyCredentialGetOptionsResponse`](#ServerPublicKeyCredentialGetOptionsResponse).  

This [`ServerPublicKeyCredentialGetOptionsResponse`](#ServerPublicKeyCredentialGetOptionsResponse) is intended to be used as the parameters to the WebAuthn [navigator.credentials.get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) call.  

The client formats the output of [`navigator.credentials.get()`](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) as a [`ServerPublicKeyCredential`](#ServerPublicKeyCredential) with `response` field set to [`ServerAuthenticatorAssertionResponse`](#ServerAuthenticatorAssertionResponse) and sends it to the server.  

The server validates the assertion according the section 7.2 of the [WebAuthn](https://w3c.github.io/webauthn/#sctn-verifying-assertion) specification, and returns the corresponding [`ServerResponse`](#ServerResponse).

### Authentication IDL
#### ServerPublicKeyCredentialGetOptionsRequest
```java
    dictionary ServerPublicKeyCredentialGetOptionsRequest {
        required DOMString                         username;
        UserVerificationRequirement                userVerification = "preferred";
        AuthenticationExtensionsClientInputs       extensions;
    };
```

* `username`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ A human-readable name for the entity. For example, "alexm", "alex.p.mueller@example.com" or "+14255551234".

* `userVerification`, of type [UserVerificationRequirement](https://w3c.github.io/webauthn/#enumdef-userverificationrequirement)  
  $~~~~~$ Can be set to "required", "preferred", "discouraged". More in [WebAuthn](https://w3c.github.io/webauthn/#enumdef-userverificationrequirement) specification. Default set to "preferred".

* `extensions`, of type [AuthenticationExtensionsClientInputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-inputs)  
  $~~~~~$ A dictionary set to [AuthenticationExtensionsClientInputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-inputs) described in WebAuthn specs.

#### ServerPublicKeyCredentialGetOptionsResponse
```java
    dictionary ServerPublicKeyCredentialGetOptionsResponse : ServerResponse {
        required DOMString                             challenge;
        unsigned long                                  timeout;
        USVString                                      rpId;
        sequence<ServerPublicKeyCredentialDescriptor>  allowCredentials = [];
        UserVerificationRequirement                    userVerification = "preferred";
        AuthenticationExtensionsClientInputs           extensions;
    };
```
* `challenge`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ A random base64url encoded challenge, that is minimum 16 bytes long, and maximum 64 bytes long

* `timeout`, of type [unsigned long](https://webidl.spec.whatwg.org/#idl-unsigned-long)  
  $~~~~~$ Operation timeout in milliseconds.

* `rpId`, of type [USVString](https://webidl.spec.whatwg.org/#idl-USVString)  
  $~~~~~$ This optional member specifies the relying party identifier claimed by the caller. If omitted, its value will be the CredentialsContainer object's relevant settings object's origin's effective domain.

* `allowCredentials`, of type sequence<[ServerPublicKeyCredentialDescriptor](#ServerPublicKeyCredentialDescriptor)>  
  $~~~~~$ A sequence of [ServerPublicKeyCredentialDescriptor](#ServerPublicKeyCredentialDescriptor) described in this document

* `userVerification`, of type [UserVerificationRequirement](https://w3c.github.io/webauthn/#enumdef-userverificationrequirement)  
  $~~~~~$ Can be set to "required", "preferred", "discouraged". More in [WebAuthn](https://w3c.github.io/webauthn/#enumdef-userverificationrequirement) specification. Default set to "preferred". Corresponds to [ServerPublicKeyCredentialGetOptionsRequest.userVerification](#ServerPublicKeyCredentialGetOptionsRequest)

* `extensions`, of type [AuthenticationExtensionsClientInputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-inputs)  
  $~~~~~$ A dictionary set to [AuthenticationExtensionsClientInputs](https://w3c.github.io/webauthn/#iface-authentication-extensions-client-inputs) described in WebAuthn specs. Corresponds to [ServerPublicKeyCredentialGetOptionsRequest.extensions](#ServerPublicKeyCredentialGetOptionsRequest)

* Extends **ServerResponse** Described in this document

#### ServerAuthenticatorAssertionResponse
```java
dictionary ServerAuthenticatorAssertionResponse : ServerAuthenticatorResponse {
    required DOMString      clientDataJSON;
    required DOMString      authenticatorData;
    required DOMString      signature;
    DOMString               userHandle;
};
```

* `clientDataJSON`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url encoded clientDataJSON buffer

* `authenticatorData`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url encoded authenticatorData buffer

* `signature`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url encoded signature buffer

* `userHandle`, of type [DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)  
  $~~~~~$ Base64url encoded userHandle buffer. Corresponding to registered user [ServerPublicKeyCredentialUserEntity.id](#ServerPublicKeyCredentialUserEntity)

## Examples

### Registration Examples
* #### [Credential Creation Options ](#registration-example-credential-creation-options)
* #### [Authenticator Attestation Response](#registration-example-authenticator-attestation-response)

### Registration Example: Credential Creation Options

**Request:**
* **URL:** /attestation/options
* **Method:** `POST`
* **URL Params:** None
* **Body:** `application/json` formatted [`ServerPublicKeyCredentialCreationOptionsRequest`](#ServerPublicKeyCredentialCreationOptionsRequest)

```json
    {
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
```

**Success Response:**
* **HTTP Status Code:** `200 OK`
* **Body:** `application/json` formatted [`ServerPublicKeyCredentialCreationOptionsResponse`](#ServerPublicKeyCredentialCreationOptionsResponse)

```json
    {
        "status": "ok",
        "errorMessage": "",
        "rp": {
            "name": "Example Corporation"
        },
        "user": {
            "id": "S3932ee31vKEC0JtJMIQ",
            "name": "johndoe@example.com",
            "displayName": "John Doe"
        },

        "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            }
        ],
        "timeout": 10000,
        "excludeCredentials": [
            {
                "type": "public-key",
                "id": "opQf1WmYAa5aupUKJIQp"
            }
        ],
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
```

**Error Response:**
* **HTTP Status Code:** `4xx or 5xx`
* **Body:** `application/json` formatted [`ServerResponse`](#ServerResponse)

```json
    {
        "status": "failed",
        "errorMessage": "Missing challenge field!"
    }
```

**Sample JavaScript:**
```javascript
    fetch('/attestation/options', {
        method  : 'POST',
        credentials : 'same-origin',
        headers : {
            'Content-Type' : 'application/json'
        },
        body: JSON.stringify({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })
    }).then(function (response) {
        return response.json();
    }).then(function (json) {
        console.log(json);
    }).catch(function (err) {
        console.log({ 'status': 'failed', 'error': err });
    })
```

### Registration Example: Authenticator Attestation Response

**Request:**
* **URL:** /attestation/result
* **Method:** `POST`
* **URL Params:** None
* **Body:** `application/json` formatted [`ServerPublicKeyCredential`](#ServerPublicKeyCredential) with `response` field set to [`ServerAuthenticatorAttestationResponse`](#ServerAuthenticatorAttestationResponse)

```json
    {
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }
```

**Success Response:**
* **HTTP Status Code:** `200 OK`
* **Body:** `application/json` formatted [`ServerResponse`](#ServerResponse)

```json
{
    "status": "ok",
    "errorMessage": ""
}
```

**Error Response:**
* **HTTP Status Code:** `4xx or 5xx`
* **Body:** `application/json` formatted [`ServerResponse`](#ServerResponse)

```json
{
    "status": "failed",
    "errorMessage": "Can not validate response signature!"
}
```

**Sample Call:**
```javascript
    fetch('/attestation/result', {
        method  : 'POST',
        credentials : 'same-origin',
        headers : {
            'Content-Type' : 'application/json'
        },
        body: JSON.stringify({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
           "getClientExtensionResults": {},
            "type": "public-key"
        })
    }).then(function (response) {
        return response.json();
    }).then(function (json) {
        console.log(json);
    }).catch(function (err) {
        console.log({ 'status': 'failed', 'error': err });
    })
```



### Authentication Examples
* #### [Credential Get Options](#authentication-example-credential-get-options)
* #### [Authenticator Assertion Response](#authentication-example-authenticator-assertion-response)

### Authentication Example: Credential Get Options

**Request:**
* **URL:** /assertion/options
* **Method:** `POST`
* **URL Params:** None
* **Body:** `application/json` encoded [`ServerPublicKeyCredentialGetOptionsRequest`](#ServerPublicKeyCredentialGetOptionsRequest)

```json
    {
        "username": "johndoe@example.com",
        "userVerification": "required"
    }
```

**Success Response:**
* **HTTP Status Code:** `200 OK`
* **Body:** `application/json` encoded [`ServerPublicKeyCredentialGetOptionsResponse`](#ServerPublicKeyCredentialGetOptionsResponse)

```json
{
    "status": "ok",
    "errorMessage": "",
    "challenge": "6283u0svT-YIF3pSolzkQHStwkJCaLKx",
    "timeout": 20000,
    "rpId": "example.com",
    "allowCredentials": [
        {
            "id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
            "type": "public-key"
        }
    ],
    "userVerification": "required"
}
```

**Error Response:**
* **HTTP Status Code:** `4xx or 5xx`
* **Body:** `application/json` encoded [`ServerResponse`](#ServerResponse)

```json
    {
        "status": "failed",
        "errorMessage": "User does not exists!"
    }
```

**Sample Call:**
```javascript
    fetch('/assertion/options', {
        method  : 'POST',
        credentials : 'same-origin',
        headers : {
            'Content-Type' : 'application/json'
        },
        body: JSON.stringify({
            "username": "johndoe@example.com",
            "userVerification": "required"
        })
    }).then(function (response) {
        return response.json();
    }).then(function (json) {
        console.log(json);
    }).catch(function (err) {
        console.log({ 'status': 'failed', 'error': err });
    })
```

### Authentication Example: Authenticator Assertion Response

**Request:**
* **URL:** /assertion/result
* **Method:** `POST`
* **URL Params:** None
* **Body:** `application/json` encoded [`ServerPublicKeyCredential`](#ServerPublicKeyCredential) with `response` field set to [`ServerAuthenticatorAssertionResponse`](#ServerAuthenticatorAssertionResponse)

```json
    {
        "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response":{
            "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle":"",
            "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type":"public-key"
    }
```

**Success Response:**
* **HTTP status code:** `200 OK`
* **Body:** `application/json` encoded [`ServerResponse`](#ServerResponse)

```json
{
    "status": "ok",
    "errorMessage": ""
}
```

**Error Response:**
* **HTTP status code:** `4xx or 5xx`
* **Body:** `application/json` encoded [`ServerResponse`](#ServerResponse)

```json
    {
        "status": "failed",
        "errorMessage": "Can not validate response signature!"
    }
```

**Sample Call:**
```javascript
    fetch('/assertion/result', {
        method  : 'POST',
        credentials : 'same-origin',
        headers : { 
            'Content-Type' : 'application/json'
        },
        body: JSON.stringify({
            "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response":{
                "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle":"",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "type":"public-key"
        })
    }).then(function (response) {
        return response.json();
    }).then(function (json) {
        console.log(json);
    }).catch(function (err) {
        console.log({ 'status': 'failed', 'error': err });
    })
```

