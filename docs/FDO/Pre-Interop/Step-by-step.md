Pre-Interop Process Step-By-Step
===

## Terms

- DO - Device Onboarding Service
- RV - Rendezvous Service
- PEM encoding - As defined in the [Voucher Encoding](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop#voucher-encoding-format)
- TO0 - A first protocol in FDO that is used by the Device Onboarding service to register network information for the device with the Rendezvous Service.
- TO1 - A second protocol in FDO that is used by the Device to get Device Owner network information,
- TO2 - A third protocol in FDO, that is used by the device to contact Device Onboarding service, and perform onboarding.

## Measure of success

A successful interop defined by
- A successful execution of TO0 between DO and RV, and a corresponding two records collected by the Dashboard.
- A successful execution of TO1 between Device and RV, and a collected record from the RV.
- A successful execution of TO2 between Device and DO, and a corresponding two records collected by the Dashboard.
- Each device model must be able to successfully perform TO1 with two distinct Rendezvous Services, that are not developed and/or run the same company.
- Each device model must be able to successfully perform TO1 with two distinct Device Onboarding services, that are not developer and/or run by the same company.
- Each Device Onboarding service must be able to register it's RVInfo with at least two distinct Rendezvous Services that are not developed and/or run by the same company.


## Setup
- Participating RV and DO vendors register with FIDO Alliance FDO Interop Dashboard and obtain access tokens to submit event logs to the dashboard.
- FIDO Alliance assigns at random two RVs per device vendor.
- Participating Device vendors, generate voucher [PEM files](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop#voucher-encoding-format), that contain PEM encoded voucher, and last OVEntry private key. THE VOUCHERS MUST HAVE AT LEAST ONE OV ENTRY
- Device vendors submit voucher files to the FIDO Alliance. FIDO Alliance then chooses at random, which DO gets which voucher, and then provides DO managers PEM files together with unique device specific access token, that DO will need to provide to the device during the ServiceInfo exchange with the ServiceInfo("fido_alliance:dev_conformance").
- Device Onboarding services MUST be able to submit voucher to ALL participating rendezvous services.


## Operational

- DO iterates over Rendezvous Service and registers network information with each RV. On success both DO and RV will submit to the dashboard a record that each of them successfully completed TO0 protocol for GUID of the device. For the LoggerEvent Nonce, both DO and RV will use the last TO0 nonce, NonceTO0Sign.
- Device wakes up and runs TO1 protocols with Rendezvous Service. On success only RV submits a record to the dashboard, since device does not have an access token. For the LoggerEvent, RV will use NonceTO1Proof.
- Device, using the network information obtained from RV, connects to the DO, and performs onboarding. During the onboarding the device will obtain dashboard access token, via ServiceInfo extension("fido_alliance:dev_conformance"). On success both Device and DO will use the last nonce in TO2, NonceTO2SetupDv.
- The Dashboard will collect events and upon successful TO0, TO1 and TO2 for specified guid, it will signal a success of interop between: DO, RV and Device.
