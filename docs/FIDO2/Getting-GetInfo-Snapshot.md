How to get GetInfo snapshot for your MDS3 metadata
===

1. Download the latest conformance test tools from [builds.fidoalliance.org](https://builds.fidoalliance.org/). Check that it's 1.6.32 or higher. (If main folder missing, check Experimental)

2. Open the test tools, and press the menu button in the top right corner.

![Test tools Menu button](./images/diag-1-tools-menu-button.png)

3. Select "Get GetInfo Snapshot" option

![Get GetInfo snapshot button](./images/diag-2-getgetinfo-button.png)

4. Insert your device into the USB port, or place it on NFC reader, or connect it via BLE. You should see it available in the device list:

![Get GetInfo snapshot button](./images/diag-3-getgetinfo-device-list.png)

5. Select device for which you would like to get GetInfo snapshot. And press "Get GetInfo":

![Get GetInfo snapshot button](./images/diag-4-getgetinfo-snapshot.png)

6. You should now see a JSON snapshot of GetInfo. Copy it to the metadata authenticatorGetInfo field and submit it via MDS3 UI.
