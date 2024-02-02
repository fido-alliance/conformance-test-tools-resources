/* -----

    THIS IS A FIDO ALLIANCE COMMON REGISTRY FILE.

    AUTHOR: YURIY ACKERMANN <YURIY@FIDOALLIANCE.ORG> <YURIY.ACKERMANN@GMAIL.COM>
    UPDATED: FEBRUARY 2ND 2024


    LICENSE

    COPYRIGHT FIDO ALLIANCE 2016-2024

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

+----- */
'use strict';

/* Contains all the short form, MDS3 registries. E.g. passcode_internal */
/* ---------- FIDO SHORT ---------- */
    /**
     * User Verification Methods Short Form
     *
     * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They describe the methods and capabilities of an UAF authenticator for locally verifying a user. The operational details of these methods are opaque to the server. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#user-verification-methods
     */
    var USER_VERIFICATION_METHODS_SHORT = {
        /* This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the presence verification provides any level of authentication of the human's identity. (e.g. a device that requires a touch to activate)*/
        0x00000001 : 'presence_internal',

        /* This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.*/
        0x00000002 : 'fingerprint_internal',

        /* This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.*/
        0x00000004 : 'passcode_internal',

        /* This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.*/
        0x00000008 : 'voiceprint_internal',

        /* This flag must be set if the authenticator uses any manner of face recognition to verify the user.*/
        0x00000010 : 'faceprint_internal',

        /* This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.*/
        0x00000020 : 'location_internal',

        /* This flag must be set if the authenticator uses any form of eye biometrics for user verification.*/
        0x00000040 : 'eyeprint_internal',

        /* This flag must be set if the authenticator uses a drawn pattern for user verification.*/
        0x00000080 : 'pattern_internal',

        /* This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.*/
        0x00000100 : 'handprint_internal',

        /* This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification that might be gathered outside the authenticator boundary. */
        0x00000800 : 'passcode_external',

        /* This flag must be set if the authenticator uses a drawn pattern for user verification that might be gathered outside the authenticator boundary. */
        0x00001000 : 'pattern_external',

        /* This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).*/
        0x00000200 : 'none',

        /* If an authenticator sets multiple flags for user verification types, it may also set this flag to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).*/
        0x00000400 : 'all'
    }


    /**
     * Key Protection Types Short Form
     *
     * The KEY_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the private key material for FIDO registrations. Refer to [UAFAuthnrCommands] for more details on the relevance of keys and key protection. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#key-protection-types
     * type {Object}
     */
    var KEY_PROTECTION_TYPES_SHORT = {

        /* This flag must be set if the authenticator uses software-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_HARDWARE, KEY_PROTECTION_TEE, KEY_PROTECTION_SECURE_ELEMENT*/
        0x0001 : 'software',

        /* This flag should be set if the authenticator uses hardware-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE*/
        0x0002 : 'hardware',

        /* This flag should be set if the authenticator uses the Trusted Execution Environment [TEE] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE, KEY_PROTECTION_SECURE_ELEMENT*/
        0x0004 : 'tee',

        /* This flag should be set if the authenticator uses a Secure Element [SecureElement] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_TEE, KEY_PROTECTION_SOFTWARE*/
        0x0008 : 'secure_element',

        /* This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client, but relies on a server-provided key handle. This flag must be set in conjunction with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations are protected. Servers may unset this flag in authenticator policy if they are not prepared to store and return key handles, for example, if they have a requirement to respond indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to [UAFProtocol] for more details.*/
        0x0010 : 'remote_handle'
    }

    /**
     * Matcher Protection Types Short Form
     *
     * The MATCHER_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the matcher that performs user verification. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the matcher component.
     * 
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#matcher-protection-types
     * 
     * type {Object}
     */
    var MATCHER_PROTECTION_TYPES_SHORT = {

        /*This flag must be set if the authenticator's matcher is running in software. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP*/
        0x0001 : 'software',
        
        /*This flag should be set if the authenticator's matcher is running inside the Trusted Execution Environment [TEE]. Exclusive in authenticator metadata with MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_ON_CHIP*/
        0x0002 : 'tee',
        
        /*This flag should be set if the authenticator's matcher is running on the chip. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_SOFTWARE*/
        0x0004 : 'on_chip'
    }

    /**
     * Authenticator Attachment Hints Short Form
     *
     * The ATTACHMENT_HINT constants are flags in a bit field represented as a 32 bit long. They describe the method an authenticator uses to communicate with the FIDO User Device. These constants are reported and queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and used to form Authenticator policies in UAF protocol messages. Because the connection state and topology of an authenticator may be transient, these values are only hints that can be used by server-supplied policy to guide the user experience, e.g. to prefer a device that is connected and ready for authenticating or confirming a low-value transaction, rather than one that is more secure but requires more user effort.
     * 
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authenticator-attachment-hints
     * 
     * type {Object}
     */
    var ATTACHMENT_HINTS_SHORT = {

        /* This flag may be set to indicate that the authenticator is permanently attached to the FIDO User Device. A device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO client must filter and exclusively report only the relevant bit during Discovery and when performing policy matching.\nThis flag cannot be combined with any other ATTACHMENT_HINT flags.*/
        0x0001 : 'internal',

        /* This flag may be set to indicate, for a hardware-based authenticator, that it is removable or remote from the FIDO User Device.\nA device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO UAF Client must filter and exclusively report only the relevant bit during discovery and when performing policy matching.*/
        0x0002 : 'external',

        /* This flag may be set to indicate that an external authenticator currently has an exclusive wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.*/
        0x0004 : 'wired',

        /* This flag may be set to indicate that an external authenticator communicates with the FIDO User Device through a personal area or otherwise non-routed wireless protocol, such as Bluetooth or NFC.*/
        0x0008 : 'wireless',

        /* This flag may be set to indicate that an external authenticator is able to communicate by NFC to the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set as well.*/
        0x0010 : 'nfc',

        /* This flag may be set to indicate that an external authenticator is able to communicate using Bluetooth with the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
        0x0020 : 'bluetooth',

        /* This flag may be set to indicate that the authenticator is connected to the FIDO User Device ver a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).*/
        0x0040 : 'network',

        /* Thif flag may be set to indicate that an external authenticator is in a "ready" state. This flag is set by the ASM at its discretion.*/
        0x0080 : 'ready',

        /* This flag may be set to indicate that an external authenticator is able to communicate using WiFi Direct with the FIDO User Device. As part of authenticator metadata and when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
        0x0100 : 'wifi_direct'
    }

    /**
     * Authentication Algorithms Short Form
     * 
     * The UAF_ALG_SIGN constants are 16 bit long integers indicating the specific signature algorithm and encoding.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authentication-algorithms
     * 
     * type {Object}
     */
    var AUTHENTICATION_ALGORITHMS_SHORT = {

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         *I.e. [R (32 bytes), S (32 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -7, crv: 1)
         *
         */
        0x0001 : 'secp256r1_ecdsa_sha256_raw',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the NIST secp256r1 curve.
         * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -7, crv: 1)
         *
         */
        0x0002 : 'secp256r1_ecdsa_sha256_der',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         * - Mask Generation Algorithm MGF1 with SHA256
         * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         ** ALG_KEY_COSE(kty: 3, alg: -37)
         *
         */
        0x0003 : 'rsassa_pss_sha256_raw',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the RSASSA-PSS [RFC3447] signature [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         * - Mask Generation Algorithm MGF1 with SHA256
         * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. a DER encoded OCTET STRING (including its tag and length bytes).
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         ** ALG_KEY_COSE(kty: 3, alg: -37)
         *
         */
        0x0004 : 'rsassa_pss_sha256_der',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
         * I.e.[R (32 bytes), S (32 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -47, crv: 8)
         *
         */
        0x0005 : 'secp256k1_ecdsa_sha256_raw',


        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
         * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -47, crv: 8)
         *
         */
        0x0006 : 'secp256k1_ecdsa_sha256_der',

        /**
         * Chinese SM2 elliptic curve based signature algorithm combined with SM3 hash algorithm [OSCCA-SM2][OSCCA-SM3]. We use the 256bit curve [OSCCA-SM2-curve-param].
         * This algorithm is suitable for authenticators using the following key representation format: ALG_KEY_ECC_X962_RAW.
         */
        0x0007 : 'sm2_sm3_raw',

        /**
         * This is the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature octets.
         ** EM = 0x00 | 0x01 | PS | 0x00 | T
         ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
         ** with the DER [ITU-X690-2008] encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         */
        0x0008 : 'rsa_emsa_pkcs1_sha256_raw',

        /**
         * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature. The raw signature is DER [ITU-X690-2008] encoded as an OCTET STRING to produce the final signature octets.
         ** EM = 0x00 | 0x01 | PS | 0x00 | T
         ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
         ** with the DER encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         */
        0x0009 : 'rsa_emsa_pkcs1_sha256_der',

        /**
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         ** Mask Generation Algorithm MGF1 with SHA384
         ** Salt Length of 48 bytes, i.e. the length of a SHA384 hash value.
         ** Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -38)
         */
        0x000A : 'rsassa_pss_sha384_raw',

        /**
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         ** Mask Generation Algorithm MGF1 with SHA512
         ** Salt Length of 64 bytes, i.e. the length of a SHA512 hash value.
         ** Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -39)
         */
        0x000B : 'rsassa_pss_sha512_raw',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA256(aka RS256) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -257)
         */
        0x000C : 'rsassa_pkcsv15_sha256_raw',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA384(aka RS384) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -258)
         */
        0x000D : 'rsassa_pkcsv15_sha384_raw',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA512(aka RS512) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -259)
         */
        0x000E : 'rsassa_pkcsv15_sha512_raw',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA1(aka RS1) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -65535)
         */
        0x000F : 'rsassa_pkcsv15_sha1_raw',

        /**
         * An ECDSA signature on the NIST secp384r1 curve with SHA384(aka: ES384) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
         * I.e. [R (48 bytes), S (48 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 2, alg: -35, crv: 2)
         */
        0x0010 : 'secp384r1_ecdsa_sha384_raw',


        /**
         * An ECDSA signature on the NIST secp521r1 curve with SHA512(aka: ES512) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
         * I.e. [R (66 bytes), S (66 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 2, alg: -36, crv: 3)
         */
        0x0011 : 'secp521r1_ecdsa_sha512_raw',

        /**
         * An EdDSA signature on the curve 25519, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
         * I.e. [R (32 bytes), S (32 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats
         ** ALG_KEY_COSE(kty: 1, alg: -8, crv: 6)
         */
        0x0012 : 'ed25519_eddsa_sha512_raw',


        /**
         * An EdDSA signature on the curve Ed448, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
         *
         * I.e. [R (57 bytes), S (57 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         *
         ** ALG_KEY_COSE(kty: 1, alg: -8, crv: 7)
         */
        0x0013: 'ed448_eddsa_sha512_raw'
    }


    /**
     * Public Key Representation Formats Short Form
     *
     * The UAF_ALG_KEY constants are 16 bit long integers indicating the specific Public Key algorithm and encoding.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#public-key-representation-formats
     * 
     * type {Object}
     */
    var PUBLIC_KEY_REPRESENTATION_FORMATS_SHORT = {

        /** 
         * Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
         * 
         * I.e. [0x04, X (32 bytes), Y (32 bytes)]. Where the byte 0x04 denotes the uncompressed point compression method.
         */
        0x100 : 'ecc_x962_raw',

        /** 
         * 
         * DER [ITU-X690-2008] encoded ANSI X.9.62 formatted SubjectPublicKeyInfo [RFC5480] specifying an elliptic curve public key.
         * 
         * I.e. a DER encoded SubjectPublicKeyInfo as defined in [RFC5480].
         * 
         * Authenticator implementations must generate namedCurve in the ECParameters object which is included in the AlgorithmIdentifier. A FIDO UAF Server must accept namedCurve in the ECParameters object which is included in the AlgorithmIdentifier.
         */
        0x101 : 'ecc_x962_der',

        /** 
         * Raw encoded RSASSA-PSS public key [RFC3447].
         * The default parameters according to [RFC4055] must be assumed, i.e.
         *
         *  - Mask Generation Algorithm MGF1 with SHA256
         *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * 
         * That is, [n (256 bytes), e (N-n bytes)]. Where N is the total length of the field.
         *
         * This total length should be taken from the object containing this key, e.g. the TLV encoded field.
         */
        0x102 : 'rsa_2048_raw',

        /** 
         * 
         * ASN.1 DER [ITU-X690-2008] encoded RSASSA-PSS [RFC3447] public key [RFC4055].
         * The default parameters according to [RFC4055] must be assumed, i.e.
         * 
         *  - Mask Generation Algorithm MGF1 with SHA256
         *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * 
         * That is, a DER encoded SEQUENCE { n INTEGER, e INTEGER }.
         */
        0x103 : 'rsa_2048_der',

        /**
         * COSE_Key format, as defined in Section 7 of [RFC8152]. This encoding includes its own field for indicating the public key algorithm.
         */
        0x104 : 'cose'
    }

        /**
     * Transaction Confirmation Display Types Short Form
     *
     * The TRANSACTION_CONFIRMATION_DISPLAY constants are flags in a bit field represented as a 16 bit long integer. They describe the availability and implementation of a transaction confirmation display capability required for the transaction confirmation operation. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the security aspects of TransactionConfirmation Display.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#transaction-confirmation-display-types
     * type {Object}
     */
    var TRANSACTION_CONFIRMATION_DISPLAY_TYPES_SHORT = {
        /* This flag must be set to indicate, that some form of transaction confirmation display is available on this authenticator.*/
        0x01 : 'any',

        /* This flag must be set to indicate, that a software-based transaction confirmation display operating in a privileged context is available on this authenticator.\nA FIDO client that is capable of providing this capability may set this bit for all authenticators of type ATTACHMENT_HINT_INTERNAL, even if the authoritative metadata for the authenticator does not indicate this capability.*/
        0x02 : 'privileged_software',

        /* This flag should be set to indicate that the authenticator implements a transaction confirmation display in a Trusted Execution Environment ([TEE], [TEESecureDisplay]).*/
        0x04 : 'tee',

        /* This flag should be set to indicate that a transaction confirmation display based on hardware assisted capabilities is available on this authenticator.*/
        0x08 : 'hardware',

        /* This flag should be set to indicate that the transaction confirmation display is provided on a distinct device from the FIDO User Device.*/
        0x10 : 'remote'
    }

    var ATTESTATION_TYPES_SHORT = {
        /* Indicates full basic attestation as defined in [UAFProtocol]. */
        0x3E07 : 'basic_full',

        /* Indicates surrogate basic attestation as defined in [UAFProtocol]. */
        0x3E08 : 'basic_surrogate',

        /* Indicates ECDAA attestation as defined in [UAFProtocol]. */
        0x3E09 : 'ecdaa',

        /* Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is optional at this time. It might be required by FIDO Certification. */
        0x3E0A : 'attca',

        /* In this case, the authenticator uses an Anonymization CA which dynamically generates per-credential attestation certificates such that the attestation statements presented to Relying Parties do not provide uniquely identifiable information, e.g., that might be used for tracking purposes. The applicable [WebAuthn] attestation formats "fmt" are Google SafetyNet Attestation "android-safetynet", Android Keystore Attestation "android-key", Apple Anonymous Attestation "apple", and Apple Application Attestation "apple-appattest". */
        0x3E0C: 'anonca',

        /* Indicates absence of attestation. */
        0x3E0B: 'none'
    }
/* ---------- FIDO SHORT ENDS ---------- */

/* Contains all the long form, legacy MDS2 registries. E.g. USER_VERIFY_PASSCODE_INTERNAL */
/* ---------- FIDO LONG ---------- */
    /**
     * User Verification Methods
     *
     * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They describe the methods and capabilities of an UAF authenticator for locally verifying a user. The operational details of these methods are opaque to the server. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#user-verification-methods
     */
    var USER_VERIFICATION_METHODS = {
        /* This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the presence verification provides any level of authentication of the human's identity. (e.g. a device that requires a touch to activate)*/
        0x00000001 : 'USER_VERIFY_PRESENCE_INTERNAL',

        /* This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.*/
        0x00000002 : 'USER_VERIFY_FINGERPRINT_INTERNAL',

        /* This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.*/
        0x00000004 : 'USER_VERIFY_PASSCODE_INTERNAL',

        /* This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.*/
        0x00000008 : 'USER_VERIFY_VOICEPRINT_INTERNAL',

        /* This flag must be set if the authenticator uses any manner of face recognition to verify the user.*/
        0x00000010 : 'USER_VERIFY_FACEPRINT_INTERNAL',

        /* This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.*/
        0x00000020 : 'USER_VERIFY_LOCATION_INTERNAL',

        /* This flag must be set if the authenticator uses any form of eye biometrics for user verification.*/
        0x00000040 : 'USER_VERIFY_EYEPRINT_INTERNAL',

        /* This flag must be set if the authenticator uses a drawn pattern for user verification.*/
        0x00000080 : 'USER_VERIFY_PATTERN_INTERNAL',

        /* This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.*/
        0x00000100 : 'USER_VERIFY_HANDPRINT_INTERNAL',

        /* This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification that might be gathered outside the authenticator boundary. */
        0x00000800 : 'USER_VERIFY_PASSCODE_EXTERNAL',

        /* This flag must be set if the authenticator uses a drawn pattern for user verification that might be gathered outside the authenticator boundary. */
        0x00001000 : 'USER_VERIFY_PATTERN_EXTERNAL',

        /* This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).*/
        0x00000200 : 'USER_VERIFY_NONE',

        /* If an authenticator sets multiple flags for user verification types, it may also set this flag to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).*/
        0x00000400 : 'USER_VERIFY_ALL'
    }


    /**
     * Key Protection Types
     *
     * The KEY_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the private key material for FIDO registrations. Refer to [UAFAuthnrCommands] for more details on the relevance of keys and key protection. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#key-protection-types
     * type {Object}
     */
    var KEY_PROTECTION_TYPES = {

        /* This flag must be set if the authenticator uses software-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_HARDWARE, KEY_PROTECTION_TEE, KEY_PROTECTION_SECURE_ELEMENT*/
        0x0001 : 'KEY_PROTECTION_SOFTWARE',

        /* This flag should be set if the authenticator uses hardware-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE*/
        0x0002 : 'KEY_PROTECTION_HARDWARE',

        /* This flag should be set if the authenticator uses the Trusted Execution Environment [TEE] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE, KEY_PROTECTION_SECURE_ELEMENT*/
        0x0004 : 'KEY_PROTECTION_TEE',

        /* This flag should be set if the authenticator uses a Secure Element [SecureElement] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_TEE, KEY_PROTECTION_SOFTWARE*/
        0x0008 : 'KEY_PROTECTION_SECURE_ELEMENT',

        /* This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client, but relies on a server-provided key handle. This flag must be set in conjunction with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations are protected. Servers may unset this flag in authenticator policy if they are not prepared to store and return key handles, for example, if they have a requirement to respond indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to [UAFProtocol] for more details.*/
        0x0010 : 'KEY_PROTECTION_REMOTE_HANDLE'
    }


    /**
     * Matcher Protection Types
     *
     * The MATCHER_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the matcher that performs user verification. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the matcher component.
     * 
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#matcher-protection-types
     * 
     * type {Object}
     */
    var MATCHER_PROTECTION_TYPES = {

        /*This flag must be set if the authenticator's matcher is running in software. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP*/
        0x0001 : 'MATCHER_PROTECTION_SOFTWARE',
        
        /*This flag should be set if the authenticator's matcher is running inside the Trusted Execution Environment [TEE]. Exclusive in authenticator metadata with MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_ON_CHIP*/
        0x0002 : 'MATCHER_PROTECTION_TEE',
        
        /*This flag should be set if the authenticator's matcher is running on the chip. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_SOFTWARE*/
        0x0004 : 'MATCHER_PROTECTION_ON_CHIP'
    }


    /**
     * Authenticator Attachment Hints
     *
     * The ATTACHMENT_HINT constants are flags in a bit field represented as a 32 bit long. They describe the method an authenticator uses to communicate with the FIDO User Device. These constants are reported and queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and used to form Authenticator policies in UAF protocol messages. Because the connection state and topology of an authenticator may be transient, these values are only hints that can be used by server-supplied policy to guide the user experience, e.g. to prefer a device that is connected and ready for authenticating or confirming a low-value transaction, rather than one that is more secure but requires more user effort.
     * 
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authenticator-attachment-hints
     * 
     * type {Object}
     */
    var ATTACHMENT_HINTS = {

        /* This flag may be set to indicate that the authenticator is permanently attached to the FIDO User Device. A device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO client must filter and exclusively report only the relevant bit during Discovery and when performing policy matching.\nThis flag cannot be combined with any other ATTACHMENT_HINT flags.*/
        0x0001 : 'ATTACHMENT_HINT_INTERNAL',

        /* This flag may be set to indicate, for a hardware-based authenticator, that it is removable or remote from the FIDO User Device.\nA device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO UAF Client must filter and exclusively report only the relevant bit during discovery and when performing policy matching.*/
        0x0002 : 'ATTACHMENT_HINT_EXTERNAL',

        /* This flag may be set to indicate that an external authenticator currently has an exclusive wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.*/
        0x0004 : 'ATTACHMENT_HINT_WIRED',

        /* This flag may be set to indicate that an external authenticator communicates with the FIDO User Device through a personal area or otherwise non-routed wireless protocol, such as Bluetooth or NFC.*/
        0x0008 : 'ATTACHMENT_HINT_WIRELESS',

        /* This flag may be set to indicate that an external authenticator is able to communicate by NFC to the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set as well.*/
        0x0010 : 'ATTACHMENT_HINT_NFC',

        /* This flag may be set to indicate that an external authenticator is able to communicate using Bluetooth with the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
        0x0020 : 'ATTACHMENT_HINT_BLUETOOTH',

        /* This flag may be set to indicate that the authenticator is connected to the FIDO User Device ver a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).*/
        0x0040 : 'ATTACHMENT_HINT_NETWORK',

        /* Thif flag may be set to indicate that an external authenticator is in a "ready" state. This flag is set by the ASM at its discretion.*/
        0x0080 : 'ATTACHMENT_HINT_READY',

        /* This flag may be set to indicate that an external authenticator is able to communicate using WiFi Direct with the FIDO User Device. As part of authenticator metadata and when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
        0x0100 : 'ATTACHMENT_HINT_WIFI_DIRECT'
    }


    /**
     * Authentication Algorithms
     * 
     * The UAF_ALG_SIGN constants are 16 bit long integers indicating the specific signature algorithm and encoding.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authentication-algorithms
     * 
     * type {Object}
     */
    var AUTHENTICATION_ALGORITHMS = {

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         *I.e. [R (32 bytes), S (32 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -7, crv: 1)
         *
         */
        0x0001 : 'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the NIST secp256r1 curve.
         * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -7, crv: 1)
         *
         */
        0x0002 : 'ALG_SIGN_SECP256R1_ECDSA_SHA256_DER',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         * - Mask Generation Algorithm MGF1 with SHA256
         * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         ** ALG_KEY_COSE(kty: 3, alg: -37)
         *
         */
        0x0003 : 'ALG_SIGN_RSASSA_PSS_SHA256_RAW',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the RSASSA-PSS [RFC3447] signature [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         * - Mask Generation Algorithm MGF1 with SHA256
         * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. a DER encoded OCTET STRING (including its tag and length bytes).
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         ** ALG_KEY_COSE(kty: 3, alg: -37)
         *
         */
        0x0004 : 'ALG_SIGN_RSASSA_PSS_SHA256_DER',

        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
         * I.e.[R (32 bytes), S (32 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -47, crv: 8)
         *
         */
        0x0005 : 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW',


        /**
         * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
         * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
         * I.e.[R (32 bytes), S (32 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_ECC_X962_RAW
         ** ALG_KEY_ECC_X962_DER
         ** ALG_KEY_COSE(kty: 2, alg: -47, crv: 8)
         *
         */
        0x0006 : 'ALG_SIGN_SECP256K1_ECDSA_SHA256_DER',

        /**
         * Chinese SM2 elliptic curve based signature algorithm combined with SM3 hash algorithm [OSCCA-SM2][OSCCA-SM3]. We use the 256bit curve [OSCCA-SM2-curve-param].
         * This algorithm is suitable for authenticators using the following key representation format: ALG_KEY_ECC_X962_RAW.
         */
        0x0007 : 'ALG_SIGN_SM2_SM3_RAW',

        /**
         * This is the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature octets.
         ** EM = 0x00 | 0x01 | PS | 0x00 | T
         ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
         ** with the DER [ITU-X690-2008] encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         */
        0x0008 : 'ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW',

        /**
         * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature. The raw signature is DER [ITU-X690-2008] encoded as an OCTET STRING to produce the final signature octets.
         ** EM = 0x00 | 0x01 | PS | 0x00 | T
         ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
         ** with the DER encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_RSA_2048_RAW
         ** ALG_KEY_RSA_2048_DER
         */
        0x0009 : 'ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER',

        /**
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         ** Mask Generation Algorithm MGF1 with SHA384
         ** Salt Length of 48 bytes, i.e. the length of a SHA384 hash value.
         ** Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -38)
         */
        0x000A : 'ALG_SIGN_RSASSA_PSS_SHA384_RAW',

        /**
         * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
         ** Mask Generation Algorithm MGF1 with SHA512
         ** Salt Length of 64 bytes, i.e. the length of a SHA512 hash value.
         ** Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -39)
         */
        0x000B : 'ALG_SIGN_RSASSA_PSS_SHA512_RAW',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA256(aka RS256) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -257)
         */
        0x000C : 'ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA384(aka RS384) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -258)
         */
        0x000D : 'ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA512(aka RS512) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -259)
         */
        0x000E : 'ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW',

        /**
         * RSASSA-PKCS1-v1_5 [RFC3447] with SHA1(aka RS1) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056]
         * I.e. [ S (256 bytes) ]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 3, alg: -65535)
         */
        0x000F : 'ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW',

        /**
         * An ECDSA signature on the NIST secp384r1 curve with SHA384(aka: ES384) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
         * I.e. [R (48 bytes), S (48 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 2, alg: -35, crv: 2)
         */
        0x0010 : 'ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW',


        /**
         * An ECDSA signature on the NIST secp521r1 curve with SHA512(aka: ES512) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
         * I.e. [R (66 bytes), S (66 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats:
         ** ALG_KEY_COSE(kty: 2, alg: -36, crv: 3)
         */
        0x0011 : 'ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW',

        /**
         * An EdDSA signature on the curve 25519, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
         * I.e. [R (32 bytes), S (32 bytes)]
         * This algorithm is suitable for authenticators using the following key representation formats
         ** ALG_KEY_COSE(kty: 1, alg: -8, crv: 6)
         */
        0x0012 : 'ALG_SIGN_ED25519_EDDSA_SHA512_RAW',

        /**
         * An EdDSA signature on the curve Ed448, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
         *
         * I.e. [R (57 bytes), S (57 bytes)]
         *
         * This algorithm is suitable for authenticators using the following key representation formats:
         *
         ** ALG_KEY_COSE(kty: 1, alg: -8, crv: 7)
         */
        0x0013: 'ALG_SIGN_ED448_EDDSA_SHA512_RAW'
    }
    

    /**
     * Public Key Representation Formats
     *
     * The UAF_ALG_KEY constants are 16 bit long integers indicating the specific Public Key algorithm and encoding.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#public-key-representation-formats
     * 
     * type {Object}
     */
    var PUBLIC_KEY_REPRESENTATION_FORMATS = {

        /** 
         * Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
         * 
         * I.e. [0x04, X (32 bytes), Y (32 bytes)]. Where the byte 0x04 denotes the uncompressed point compression method.
         */
        0x100 : 'ALG_KEY_ECC_X962_RAW',

        /** 
         * 
         * DER [ITU-X690-2008] encoded ANSI X.9.62 formatted SubjectPublicKeyInfo [RFC5480] specifying an elliptic curve public key.
         * 
         * I.e. a DER encoded SubjectPublicKeyInfo as defined in [RFC5480].
         * 
         * Authenticator implementations must generate namedCurve in the ECParameters object which is included in the AlgorithmIdentifier. A FIDO UAF Server must accept namedCurve in the ECParameters object which is included in the AlgorithmIdentifier.
         */
        0x101 : 'ALG_KEY_ECC_X962_DER',

        /** 
         * Raw encoded RSASSA-PSS public key [RFC3447].
         * The default parameters according to [RFC4055] must be assumed, i.e.
         *
         *  - Mask Generation Algorithm MGF1 with SHA256
         *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * 
         * That is, [n (256 bytes), e (N-n bytes)]. Where N is the total length of the field.
         *
         * This total length should be taken from the object containing this key, e.g. the TLV encoded field.
         */
        0x102 : 'ALG_KEY_RSA_2048_PSS_RAW',

        /** 
         * 
         * ASN.1 DER [ITU-X690-2008] encoded RSASSA-PSS [RFC3447] public key [RFC4055].
         * The default parameters according to [RFC4055] must be assumed, i.e.
         * 
         *  - Mask Generation Algorithm MGF1 with SHA256
         *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
         *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
         * 
         * That is, a DER encoded SEQUENCE { n INTEGER, e INTEGER }.
         */
        0x103 : 'ALG_KEY_RSA_2048_PSS_DER',

        /**
         * COSE_Key format, as defined in Section 7 of [RFC8152]. This encoding includes its own field for indicating the public key algorithm.
         */
        0x104 : 'ALG_KEY_COSE'
    }


    /**
     * Transaction Confirmation Display Types
     *
     * The TRANSACTION_CONFIRMATION_DISPLAY constants are flags in a bit field represented as a 16 bit long integer. They describe the availability and implementation of a transaction confirmation display capability required for the transaction confirmation operation. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the security aspects of TransactionConfirmation Display.
     *
     * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#transaction-confirmation-display-types
     * type {Object}
     */
    var TRANSACTION_CONFIRMATION_DISPLAY_TYPES = {
        /* This flag must be set to indicate, that some form of transaction confirmation display is available on this authenticator.*/
        0x01 : 'TRANSACTION_CONFIRMATION_DISPLAY_ANY',

        /* This flag must be set to indicate, that a software-based transaction confirmation display operating in a privileged context is available on this authenticator.\nA FIDO client that is capable of providing this capability may set this bit for all authenticators of type ATTACHMENT_HINT_INTERNAL, even if the authoritative metadata for the authenticator does not indicate this capability.*/
        0x02 : 'TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE',

        /* This flag should be set to indicate that the authenticator implements a transaction confirmation display in a Trusted Execution Environment ([TEE], [TEESecureDisplay]).*/
        0x04 : 'TRANSACTION_CONFIRMATION_DISPLAY_TEE',

        /* This flag should be set to indicate that a transaction confirmation display based on hardware assisted capabilities is available on this authenticator.*/
        0x08 : 'TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE',

        /* This flag should be set to indicate that the transaction confirmation display is provided on a distinct device from the FIDO User Device.*/
        0x10 : 'TRANSACTION_CONFIRMATION_DISPLAY_REMOTE'
    }


    var ATTESTATION_TYPES = {
        /* Indicates full basic attestation as defined in [UAFProtocol]. */
        0x3E07 : 'ATTESTATION_BASIC_FULL',

        /* Indicates surrogate basic attestation as defined in [UAFProtocol]. */
        0x3E08 : 'ATTESTATION_BASIC_SURROGATE',

        /* Indicates ECDAA attestation as defined in [UAFProtocol]. */
        0x3E09 : 'ATTESTATION_ECDAA',

        /* Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is optional at this time. It might be required by FIDO Certification. */
        0x3E0A : 'ATTESTATION_ATTCA',

        /* In this case, the authenticator uses an Anonymization CA which dynamically generates per-credential attestation certificates such that the attestation statements presented to Relying Parties do not provide uniquely identifiable information, e.g., that might be used for tracking purposes. The applicable [WebAuthn] attestation formats "fmt" are Google SafetyNet Attestation "android-safetynet", Android Keystore Attestation "android-key", Apple Anonymous Attestation "apple", and Apple Application Attestation "apple-appattest". */
        0x3E0C: 'ATTESTATION_ANONCA',

        /* Indicates absence of attestation. */
        0x3E0B: 'ATTESTATION_NONE'

    }

    var AUTHENTICATOR_ALLOWED_RESTRICTED_OPERATING_ENVIRONMENTS_LIST = [
        /* All operating systems (ROE firmware) running on ARM TrustZone HW are accepted as AROE as required for Level 2 FIDO Authenticator Certification. See ARM TrustZone Security Whitepaper and ARM Architecture Reference Manual. */
        'TEEs based on ARM TrustZone HW',

        /* All operating systems (ROE firmware) running on Intel VT HW are accepted as AROE as required for Level 2 FIDO Authenticator Certification. See Intel Vanderpool Technology for IA-32 Processors (VT-x) Preliminary Specification. */
        'TEE Based on Intel VT HW',

        /* All operating systems (ROE firmware) running on Intel SGX HW are accepted as AROE as required for Level 2 FIDO Authenticator Certification. See Innovative Instructions and Software Model for Isolated Execution and Innovative Technology for CPU based Attestation and Sealing. */
        'TEE Based on Intel SGX HW',

        /* All operating systems (ROE firmware) running on Intel ME/TXE HW are accepted as AROE as required for Level 2 FIDO Authenticator Certification. See Intel’s Embedded Solutions: from Management to Security*/
        'TEE Based on Intel ME/TXE HW',

        /* GlobalPlatform TEE Protection Profile Certification is NOT required for Level 2 FIDO Authenticator Certification, but it is sufficient for any TEE to be qualified as an Allowed Restricted Operating Environment. See TEE Protection Profile v1.2.1*/
        'TEE with GlobalPlatform TEE Protection Profile Certification',

        /* Security apps and services that are running at Virtual Trust Level 1 are accepted as AROE as required for Level 2 FIDO Authenticator Certification See Moore Defeating - Pass the Hash Separation of Powers. */
        'Windows 10 Virtualization-based Security',

        /* All operating environments running on the secure world side of the TrustZone in the AMD PSP. See AMD Secure Technology. */
        'Secure World of AMD PSP (Platform Security coProcessor)',

        /* For example, TPM Main Specification Version 1.2 [TPM] or TPM Library Specification Version 2.0 [TPMv2] are accepted as AROE as required for Level 2 FIDO Authenticator Certification. */
        'Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications',

        /* Secure Operating Systems (ROE firmware) running on a secure tamper-resistant microcontroller are accepted as AROE as required for Level 2 FIDO Authenticator Certification. */
        'Secure Element (SE)'
    ]
/* ---------- FIDO LONG ENDS ---------- */

/* Contains all the COSE registries and mappings */
/* ---------- COSE ---------- */
    /**
     * COSE struct keys definitions
     * @type {Object}
     */
    var COSE_KEYS = {
        'kty' : 1,
        'alg' : 3,
        'crv' : -1,
        'x'   : -2,
        'y'   : -3,
        'n'   : -1,
        'e'   : -2
    }

    /**
     * COSE key type definition
     * @type {Object}
     */
    var COSE_KTY = {
        'OKP': 1, // https://tools.ietf.org/html/rfc8152#section-13
        'EC2': 2, // https://tools.ietf.org/html/rfc8152#section-13
        'RSA': 3  // https://tools.ietf.org/html/rfc8230#section-4
    }

    /**
     * https://tools.ietf.org/html/rfc8152#section-13.1
     * COSE curve definition
     * @type {Object}
     */
    var COSE_CRV = {
        'P-256': 1, // NIST P-256 also known as secp256r1
        'P-384': 2, // NIST P-384 also known as secp384r1
        'P-521': 3,  // NIST P-521 also known as secp521r1
        'secp256k1': 8,  // SECG SC secp256k1
    }

    /**
     * COSE Algorithms for RSA
     * @type {Object}
     */
    var COSE_ALG_RSA = {
        'RS256': -257, // RSASSA-PKCS1-v1_5 w/ SHA-256 Section 8.2 of [RFC8017]
        'RS384': -258, // RSASSA-PKCS1-v1_5 w/ SHA-384 Section 8.2 of [RFC8017]
        'RS512': -259, // RSASSA-PKCS1-v1_5 w/ SHA-512 Section 8.2 of [RFC8017]
        'RS1': -65535,   // RSASSA-PKCS1-v1_5 w/ SHA-1 Section 8.2 of [RFC8017]
        'PS512': -39,  // RSASSA-PSS w/ SHA-512  [RFC8230]
        'PS384': -38,  // RSASSA-PSS w/ SHA-384 [RFC8230]
        'PS256': -37   // RSASSA-PSS w/ SHA-256 [RFC8230]
    }

    /**
     * COSE Algorithms for EC2
     * @type {Object}
     */
    var COSE_ALG_EC2 = {
        'ED256': -260, // TPM_ECC_BN_P256 curve w/ SHA-256
        'ED512': -261, // ECC_BN_ISOP512 curve w/ SHA-512
        'ES256': -7,   // ECDSA w/ SHA-256 
        'ES384': -35,  // ECDSA w/ SHA-384 
        'ES512': -36,  // ECDSA w/ SHA-512
        'ES256K': -47,   // ECDSA w/ secp256k1 curve w/ SHA-256
        'ECDH-ES+HKDF-256': -25
    }

      /**
     * COSE params to FIDO ALG mapper
     * @type {Object}
     */
    var COSE_PARAM_TO_FIDO_ALG = {
        'alg:-7,crv:1': 'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW',
        'alg:-7,crv:8': 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW',
        'alg:-47,crv:8': 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW',
        'alg:-47': 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW',
        'alg:-37': 'ALG_SIGN_RSASSA_PSS_SHA256_RAW',
        'alg:-38': 'ALG_SIGN_RSASSA_PSS_SHA384_RAW',
        'alg:-39': 'ALG_SIGN_RSASSA_PSS_SHA512_RAW',
        'alg:-257': 'ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW',
        'alg:-258': 'ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW',
        'alg:-259': 'ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW',
        'alg:-65535': 'ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW',
        'alg:-35,crv:2': 'ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW',
        'alg:-36,crv:3': 'ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW',
        'alg:-8,crv:6': 'ALG_SIGN_ED25519_EDDSA_SHA512_RAW',
        'alg:-8,crv:7': 'ALG_SIGN_ED448_EDDSA_SHA512_RAW'
    }

    /**
     * COSE params to FIDO ALG SHORT mapper
     * @type {Object}
     */
    var COSE_PARAM_TO_FIDO_ALG_SHORT = {
        'alg:-7,crv:1': 'secp256r1_ecdsa_sha256_raw',
        'alg:-47,crv:8': 'secp256k1_ecdsa_sha256_raw',
        'alg:-47': 'secp256k1_ecdsa_sha256_raw',
        'alg:-37': 'rsassa_pss_sha256_raw',
        'alg:-38': 'rsassa_pss_sha384_raw',
        'alg:-39': 'rsassa_pss_sha512_raw',
        'alg:-257': 'rsassa_pkcsv15_sha256_raw',
        'alg:-258': 'rsassa_pkcsv15_sha384_raw',
        'alg:-259': 'rsassa_pkcsv15_sha512_raw',
        'alg:-65535': 'rsassa_pkcsv15_sha1_raw',
        'alg:-35,crv:2': 'secp384r1_ecdsa_sha384_raw',
        'alg:-36,crv:3': 'secp521r1_ecdsa_sha512_raw',
        'alg:-8,crv:6': 'ed25519_eddsa_sha512_raw',
        'alg:-8,crv:7': 'ed448_eddsa_sha512_raw'
    }


    /**
     * Takes COSE identificator and returns hash function name
     * @type {Object}
     */
    var COSE_ALG_HASH = {
        '-257': 'SHA-256',  // RSASSA-PKCS1-v1_5 w/ SHA-256 Section 8.2 of [RFC8017]
        '-258': 'SHA-384',  // RSASSA-PKCS1-v1_5 w/ SHA-384 Section 8.2 of [RFC8017]
        '-259': 'SHA-512',  // RSASSA-PKCS1-v1_5 w/ SHA-512 Section 8.2 of [RFC8017]
        '-65535': 'SHA-1',  // RSASSA-PKCS1-v1_5 w/ SHA-1 Section 8.2 of [RFC8017]
        '-39': 'SHA-512',   // RSASSA-PSS w/ SHA-512  [RFC8230]
        '-38': 'SHA-384',   // RSASSA-PSS w/ SHA-384 [RFC8230]
        '-37': 'SHA-256',   // RSASSA-PSS w/ SHA-256 [RFC8230]
        '-260': 'SHA-256',  // TPM_ECC_BN_P256 curve w/ SHA-256
        '-261': 'SHA-512',  // ECC_BN_ISOP512 curve w/ SHA-512
        '-7': 'SHA-256',    // ECDSA w/ SHA-256 
        '-35': 'SHA-384',   // ECDSA w/ SHA-384 
        '-36': 'SHA-512',   // ECDSA w/ SHA-512
        '-8': 'SHA-512'     // EDDSA w/ SHA-512
    }

    var FIDO_ALG_TO_COSE = {
        'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW': {
            kty: 2,
            alg: -7,
            crv: 1,
            hashAlg: 'SHA-256',
            curve: 'p256'
        },
        'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW': {
            kty: 2,
            alg: -47,
            crv: 8,
            hashAlg: 'SHA-256',
            curve: 'secp256k1'
        },
        'ALG_SIGN_RSASSA_PSS_SHA256_RAW': {
            kty: 3,
            alg: -37,
            jwtAlg: 'PS256',
            hashAlg: 'SHA-256',
            signingScheme: 'pss-sha256',
            signAlg: 'RSA-PSS'
        },
        'ALG_SIGN_RSASSA_PSS_SHA384_RAW': {
            kty: 3,
            alg: -38,
            jwtAlg: 'PS384',
            hashAlg: 'SHA-384',
            signingScheme: 'pss-sha384',
            signAlg: 'RSA-PSS'
        },
        'ALG_SIGN_RSASSA_PSS_SHA512_RAW': {
            kty: 3,
            alg: -39,
            jwtAlg: 'PS512',
            hashAlg: 'SHA-512',
            signingScheme: 'pss-sha512',
            signAlg: 'RSA-PSS'
        },
        'ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW': {
            kty: 3,
            alg: -257,
            jwtAlg: 'RS256',
            hashAlg: 'SHA-256',
            signingScheme: 'pkcs1-sha256',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW': {
            kty: 3,
            alg: -258,
            jwtAlg: 'RS384',
            hashAlg: 'SHA-384',
            signingScheme: 'pkcs1-sha384',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW': {
            kty: 3,
            alg: -259,
            jwtAlg: 'RS512',
            hashAlg: 'SHA-512',
            signingScheme: 'pkcs1-sha512',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW': {
            kty: 3,
            alg: -65535,
            jwtAlg: 'RS1',
            hashAlg: 'SHA-1',
            signingScheme: 'pkcs1-sha1',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW': {
            kty: 2,
            alg: -35,
            crv: 2,
            hashAlg: 'SHA-384',
            curve: 'p384',
        },
        'ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW': {
            kty: 2,
            alg: -36,
            crv: 3,
            hashAlg: 'SHA-512',
            curve: 'p521'
        },
        'ALG_SIGN_ED25519_EDDSA_SHA512_RAW': {
            kty: 1,
            alg: -8,
            crv: 6,
            hashAlg: 'SHA-512',
            curve: 'curve25519'
        },
        'ALG_SIGN_ED448_EDDSA_SHA512_RAW': {
            kty: 1,
            alg: -8,
            crv: 7,
            hashAlg: 'SHA-512',
            curve: 'curve448'
        }
    }

    var FIDO_ALG_SHORT_TO_COSE = {
        'secp256r1_ecdsa_sha256_raw': {
            kty: 2,
            alg: -7,
            crv: 1,
            hashAlg: 'SHA-256',
            curve: 'p256'
        },
        'secp256k1_ecdsa_sha256_raw': {
            kty: 2,
            alg: -47,
            crv: 8,
            hashAlg: 'SHA-256',
            curve: 'secp256k1'
        },
        'rsassa_pss_sha256_raw': {
            kty: 3,
            alg: -37,
            jwtAlg: 'PS256',
            hashAlg: 'SHA-256',
            signingScheme: 'pss-sha256',
            signAlg: 'RSA-PSS'
        },
        'rsassa_pss_sha384_raw': {
            kty: 3,
            alg: -38,
            jwtAlg: 'PS384',
            hashAlg: 'SHA-384',
            signingScheme: 'pss-sha384',
            signAlg: 'RSA-PSS'
        },
        'rsassa_pss_sha512_raw': {
            kty: 3,
            alg: -39,
            jwtAlg: 'PS512',
            hashAlg: 'SHA-512',
            signingScheme: 'pss-sha512',
            signAlg: 'RSA-PSS'
        },
        'rsassa_pkcsv15_sha256_raw': {
            kty: 3,
            alg: -257,
            jwtAlg: 'RS256',
            hashAlg: 'SHA-256',
            signingScheme: 'pkcs1-sha256',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'rsassa_pkcsv15_sha384_raw': {
            kty: 3,
            alg: -258,
            jwtAlg: 'RS384',
            hashAlg: 'SHA-384',
            signingScheme: 'pkcs1-sha384',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'rsassa_pkcsv15_sha512_raw': {
            kty: 3,
            alg: -259,
            jwtAlg: 'RS512',
            hashAlg: 'SHA-512',
            signingScheme: 'pkcs1-sha512',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'rsassa_pkcsv15_sha1_raw': {
            kty: 3,
            alg: -65535,
            jwtAlg: 'RS1',
            hashAlg: 'SHA-1',
            signingScheme: 'pkcs1-sha1',
            signAlg: 'RSASSA-PKCS1-v1_5'
        },
        'secp384r1_ecdsa_sha384_raw': {
            kty: 2,
            alg: -35,
            crv: 2,
            hashAlg: 'SHA-384',
            curve: 'p384',
        },
        'secp521r1_ecdsa_sha512_raw': {
            kty: 2,
            alg: -36,
            crv: 3,
            hashAlg: 'SHA-512',
            curve: 'p521'
        },
        'ed25519_eddsa_sha512_raw': {
            kty: 1,
            alg: -8,
            crv: 6,
            hashAlg: 'SHA-512',
            curve: 'curve25519'
        },
        'ed448_eddsa_sha512_raw': {
            kty: 1,
            alg: -8,
            crv: 7,
            hashAlg: 'SHA-512',
            curve: 'curve448'
        }
    }
/* ---------- COSE ENDS ---------- */

/* Contains all TPM registries */
/* ---------- TPM ---------- */
    var TPM_ALG_ID = {
        0x0000: 'TPM_ALG_ERROR',
        0x0001: 'TPM_ALG_RSA',
        0x0004: 'TPM_ALG_SHA',
        0x0004: 'TPM_ALG_SHA1',
        0x0005: 'TPM_ALG_HMAC',
        0x0006: 'TPM_ALG_AES',
        0x0007: 'TPM_ALG_MGF1',
        0x0008: 'TPM_ALG_KEYEDHASH',
        0x000A: 'TPM_ALG_XOR',
        0x000B: 'TPM_ALG_SHA256',
        0x000C: 'TPM_ALG_SHA384',
        0x000D: 'TPM_ALG_SHA512',
        0x0010: 'TPM_ALG_NULL',
        0x0012: 'TPM_ALG_SM3_256',
        0x0013: 'TPM_ALG_SM4',
        0x0014: 'TPM_ALG_RSASSA',
        0x0015: 'TPM_ALG_RSAES',
        0x0016: 'TPM_ALG_RSAPSS',
        0x0017: 'TPM_ALG_OAEP',
        0x0018: 'TPM_ALG_ECDSA',
        0x0019: 'TPM_ALG_ECDH',
        0x001A: 'TPM_ALG_ECDAA',
        0x001B: 'TPM_ALG_SM2',
        0x001C: 'TPM_ALG_ECSCHNORR',
        0x001D: 'TPM_ALG_ECMQV',
        0x0020: 'TPM_ALG_KDF1_SP800_56A',
        0x0021: 'TPM_ALG_KDF2',
        0x0022: 'TPM_ALG_KDF1_SP800_108',
        0x0023: 'TPM_ALG_ECC',
        0x0025: 'TPM_ALG_SYMCIPHER',
        0x0026: 'TPM_ALG_CAMELLIA',
        0x0040: 'TPM_ALG_CTR',
        0x0041: 'TPM_ALG_OFB',
        0x0042: 'TPM_ALG_CBC',
        0x0043: 'TPM_ALG_CFB',
        0x0044: 'TPM_ALG_ECB'
    }

    var TPM_ECC_CURVE = {
        0x0000: 'TPM_ECC_NONE',
        0x0001: 'TPM_ECC_NIST_P192',
        0x0002: 'TPM_ECC_NIST_P224',
        0x0003: 'TPM_ECC_NIST_P256',
        0x0004: 'TPM_ECC_NIST_P384',
        0x0005: 'TPM_ECC_NIST_P521',
        0x0010: 'TPM_ECC_BN_P256',
        0x0011: 'TPM_ECC_BN_P638',
        0x0020: 'TPM_ECC_SM2_P256'
    }

    var TPM_CC = {
        0x0000011F :'TPM_CC_FIRST',
        0x0000011F :'TPM_CC_NV_UndefineSpaceSpecial',
        0x00000120 :'TPM_CC_EvictControl',
        0x00000121 :'TPM_CC_HierarchyControl',
        0x00000122 :'TPM_CC_NV_UndefineSpace',
        0x00000124 :'TPM_CC_ChangeEPS',
        0x00000125 :'TPM_CC_ChangePPS',
        0x00000126 :'TPM_CC_Clear',
        0x00000127 :'TPM_CC_ClearControl',
        0x00000128 :'TPM_CC_ClockSet',
        0x00000129 :'TPM_CC_HierarchyChangeAuth',
        0x0000012A :'TPM_CC_NV_DefineSpace',
        0x0000012B :'TPM_CC_PCR_Allocate',
        0x0000012C :'TPM_CC_PCR_SetAuthPolicy',
        0x0000012D :'TPM_CC_PP_Commands',
        0x0000012E :'TPM_CC_SetPrimaryPolicy',
        0x0000012F :'TPM_CC_FieldUpgradeStart',
        0x00000130 :'TPM_CC_ClockRateAdjust',
        0x00000131 :'TPM_CC_CreatePrimary',
        0x00000132 :'TPM_CC_NV_GlobalWriteLock',
        0x00000133 :'TPM_CC_GetCommandAuditDigest',
        0x00000134 :'TPM_CC_NV_Increment',
        0x00000135 :'TPM_CC_NV_SetBits',
        0x00000136 :'TPM_CC_NV_Extend',
        0x00000137 :'TPM_CC_NV_Write',
        0x00000138 :'TPM_CC_NV_WriteLock',
        0x00000139 :'TPM_CC_DictionaryAttackLockReset',
        0x0000013A :'TPM_CC_DictionaryAttackParameters',
        0x0000013B :'TPM_CC_NV_ChangeAuth',
        0x0000013C: 'TPM_CC_PCR_Event',
        0x0000013D: 'TPM_CC_PCR_Reset',
        0x0000013E: 'TPM_CC_SequenceComplete',
        0x0000013F: 'TPM_CC_SetAlgorithmSet',
        0x00000140: 'TPM_CC_SetCommandCodeAuditStatus',
        0x00000141: 'TPM_CC_FieldUpgradeData',
        0x00000142: 'TPM_CC_IncrementalSelfTest',
        0x00000143: 'TPM_CC_SelfTest',
        0x00000144: 'TPM_CC_Startup',
        0x00000145: 'TPM_CC_Shutdown',
        0x00000146: 'TPM_CC_StirRandom',
        0x00000147: 'TPM_CC_ActivateCredential',
        0x00000148: 'TPM_CC_Certify',
        0x00000149: 'TPM_CC_PolicyNV',
        0x0000014A: 'TPM_CC_CertifyCreation',
        0x0000014B: 'TPM_CC_Duplicate',
        0x0000014C: 'TPM_CC_GetTime',
        0x0000014D: 'TPM_CC_GetSessionAuditDigest',
        0x0000014E: 'TPM_CC_NV_Read',
        0x0000014F: 'TPM_CC_NV_ReadLock',
        0x00000150: 'TPM_CC_ObjectChangeAuth',
        0x00000151: 'TPM_CC_PolicySecret',
        0x00000152: 'TPM_CC_Rewrap',
        0x00000153: 'TPM_CC_Create',
        0x00000154: 'TPM_CC_ECDH_ZGen',
        0x00000155: 'TPM_CC_HMAC',
        0x00000156: 'TPM_CC_Import',
        0x00000157: 'TPM_CC_Load',
        0x00000158: 'TPM_CC_Quote',
        0x00000159: 'TPM_CC_RSA_Decrypt',
        0x0000015B: 'TPM_CC_HMAC_Start',
        0x0000015C: 'TPM_CC_SequenceUpdate',
        0x0000015D: 'TPM_CC_Sign',
        0x0000015E: 'TPM_CC_Unseal',
        0x00000161: 'TPM_CC_PolicySigned',
        0x00000162: 'TPM_CC_ContextLoad',
        0x00000163: 'TPM_CC_ContextSave',
        0x00000164: 'TPM_CC_ECDH_KeyGen',
        0x00000165: 'TPM_CC_EncryptDecrypt',
        0x00000166: 'TPM_CC_FlushContext',
        0x00000167: 'TPM_CC_LoadExternal',
        0x00000168: 'TPM_CC_MakeCredential',
        0x00000169: 'TPM_CC_NV_ReadPublic',
        0x0000016A: 'TPM_CC_PolicyAuthorize',
        0x0000016B: 'TPM_CC_PolicyAuthValue',
        0x0000016C: 'TPM_CC_PolicyCommandCode',
        0x0000016D: 'TPM_CC_PolicyCounterTimer',
        0x0000016E: 'TPM_CC_PolicyCpHash',
        0x0000016F: 'TPM_CC_PolicyLocality',
        0x00000170: 'TPM_CC_PolicyNameHash',
        0x00000171: 'TPM_CC_PolicyOR',
        0x00000172: 'TPM_CC_PolicyTicket',
        0x00000173: 'TPM_CC_ReadPublic',
        0x00000174: 'TPM_CC_RSA_Encrypt',
        0x00000175: 'TPM_CC_StartAuthSession',
        0x00000176: 'TPM_CC_VerifySignature',
        0x00000177: 'TPM_CC_ECC_Parameters',
        0x00000178: 'TPM_CC_FirmwareRead',
        0x00000179: 'TPM_CC_GetCapability',
        0x0000017A: 'TPM_CC_GetRandom',
        0x0000017B: 'TPM_CC_GetTestResult',
        0x0000017C: 'TPM_CC_Hash',
        0x0000017D: 'TPM_CC_PCR_Read',
        0x0000017E: 'TPM_CC_PolicyPCR',
        0x0000017F: 'TPM_CC_PolicyRestart',
        0x00000190: 'TPM_CC_ReadClock',
        0x00000191: 'TPM_CC_PCR_Extend',
        0x00000192: 'TPM_CC_PCR_SetAuthValue',
        0x00000193: 'TPM_CC_NV_Certify',
        0x00000185: 'TPM_CC_EventSequenceComplete',
        0x00000186: 'TPM_CC_HashSequenceStart',
        0x00000187: 'TPM_CC_PolicyPhysicalPresence',
        0x00000188: 'TPM_CC_PolicyDuplicationSelect',
        0x00000189: 'TPM_CC_PolicyGetDigest',
        0x0000018A: 'TPM_CC_TestParms',
        0x0000018B: 'TPM_CC_Commit',
        0x0000018C: 'TPM_CC_PolicyPassword',
        0x0000018D: 'TPM_CC_ZGen_2Phase',
        0x0000018E: 'TPM_CC_EC_Ephemeral',
        0x0000018F: 'TPM_CC_PolicyNvWritten',
        0x00000190: 'TPM_CC_PolicyTemplate',
        0x00000191: 'TPM_CC_CreateLoaded',
        0x00000192: 'TPM_CC_PolicyAuthorizeNV',
        0x00000193: 'TPM_CC_EncryptDecrypt2'
    }

    var TPM_ST = {
        0x00C4: 'TPM_ST_RSP_COMMAND',
        0X8000: 'TPM_ST_NULL',
        0x8001: 'TPM_ST_NO_SESSIONS',
        0x8002: 'TPM_ST_SESSIONS',
        0x8014: 'TPM_ST_ATTEST_NV',
        0x8015: 'TPM_ST_ATTEST_COMMAND_AUDIT',
        0x8016: 'TPM_ST_ATTEST_SESSION_AUDIT',
        0x8017: 'TPM_ST_ATTEST_CERTIFY',
        0x8018: 'TPM_ST_ATTEST_QUOTE',
        0x8019: 'TPM_ST_ATTEST_TIME',
        0x801A: 'TPM_ST_ATTEST_CREATION',
        0x8021: 'TPM_ST_CREATION',
        0x8022: 'TPM_ST_VERIFIED',
        0x8023: 'TPM_ST_AUTH_SECRET',
        0x8024: 'TPM_ST_HASHCHECK',
        0x8025: 'TPM_ST_AUTH_SIGNED',
        0x8029: 'TPM_ST_FU_MANIFEST'
    }

    var TPM_GENERATED_VALUE = 0xff544347;
/* ---------- TPM ENDS ---------- */
