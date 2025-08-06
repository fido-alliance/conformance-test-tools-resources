# Pre-Interop Process Step-By-Step

## Terms

- DO - Device Onboarding Service
- RV - Rendezvous Service
- PEM encoding - As defined in the [Voucher Encoding](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop#voucher-encoding-format)
- TO0 - A first protocol in FDO that is used by the Device Onboarding service to register network information for the device with the Rendezvous Service.
- TO1 - A second protocol in FDO that is used by the Device to get Device Owner network information,
- TO2 - A third protocol in FDO, that is used by the device to contact Device Onboarding service, and perform onboarding.

## Entities involved

- **Vendors:**
  - Device Owner (DO)
  - Rendezvous Server (RV)
  - Device
- **Tooling:**
  - FDO Interop Dashboard

## Goal

Verify that each **triplet** (Device, DO, RV) is **fully compliant** and that all three FDO protocols (TO0, TO1, TO2) have been correctly executed:

## Measure of success

| Step    | Success Criteria                                                                                     |
| ------- | ---------------------------------------------------------------------------------------------------- |
| **TO0** | DO and RV have submitted matching logs (same GUID and nonce)                                         |
| **TO1** | RV has submitted a log showing it provided redirect instructions to the Device                       |
| **TO2** | Device and DO have submitted matching logs (common nonce); DO issued SIM with access token to logger |

### Expected Logs

| Protocol | Expected Logger Events        |
| -------- | ----------------------------- |
| **TO0**  | 2 events — from DO and RV     |
| **TO1**  | 1 event — from RV             |
| **TO2**  | 2 events — from Device and DO |

### FIDO Requirements

FIDO Alliance Require:

- Each **Device**:
  - Must interact with **2+ distinct RV vendors** for TO1
  - Must complete TO2 with **2+ distinct DO vendors**
- Each **DO**:
  - Must register TO0 with **2+ distinct RV vendors**

Since there is no easy way to modify the device, this means that each device vendor must provide two distinct devices for the interop.

## Voucher, SIM and Logger support

- Vouchers must be encoded in PEM format and contain last OVEntry's private key (as defined in https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop#voucher-encoding-format).
- Vendors must support Dashboard API
  https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FDO/Pre-Interop/Dashboard-API.md
- Device Onboarding Services, and Devices must support FIDO Alliance Conformance Service Info Module
  https://github.com/fido-alliance/conformance-test-tools-resources/tree/main/docs/FDO/Pre-Interop#conformance-service-info

## Setup

- Participating RV and DO vendors register with FIDO Alliance FDO Interop Dashboard and obtain access tokens to submit event logs to the dashboard.
- FIDO Alliance assigns at random two RVs per device vendor.
- Participating Device vendors generate vouchers [PEM files](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop#voucher-encoding-format), that contain PEM encoded voucher, and last OVEntry private key. THE VOUCHERS MUST HAVE AT LEAST ONE OV ENTRY
- Device vendors submit voucher files to the FIDO Alliance. FIDO Alliance then chooses at random, which DO gets which voucher, and then provides DO managers PEM files together with unique device specific access token, that DO will need to provide to the device during the ServiceInfo exchange with the ServiceInfo("fido_alliance:dev_conformance").
- Device Onboarding services MUST be able to submit voucher to ALL participating rendezvous services.

## Operational

- DO iterates over Rendezvous Service and registers network information with each RV. On success both DO and RV will submit to the dashboard a record that each of them successfully completed TO0 protocol for GUID of the device. For the LoggerEvent Nonce, both DO and RV will use the last TO0 nonce, NonceTO0Sign.
- Device wakes up and runs TO1 protocols with Rendezvous Service. On success only RV submits a record to the dashboard, since device does not have an access token. For the LoggerEvent, RV will use NonceTO1Proof.
- Device, using the network information obtained from RV, connects to the DO, and performs onboarding. During the onboarding the device will obtain dashboard access token, via ServiceInfo extension("fido_alliance:dev_conformance"). On success both Device and DO will use the last nonce in TO2, NonceTO2SetupDv.
- The Dashboard will collect events and upon successful TO0, TO1 and TO2 for specified guid, it will signal a success of interop between: DO, RV and Device.
