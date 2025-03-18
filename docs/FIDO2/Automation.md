# Test Automation

Starting with v1.7.24 desktop FIDO Conformance Tools provide an option to enable test automation. To fully utilize this feature, you will likely require additional custom-made peripheral hardware.

## What does it do?
When enabled, test automation minimizes user interaction and reduces manual input when running the tests. Instead of relying on popup dialogs and manual user interaction, conformance tools broadcast requests over http via POST for authenticator powercycle, user precence test etc. The idea is that these actions will be handled by an additional peripheral device instead of human action.

## How to toggle test automation
1. Open toaster menu in the top-right corner.
2. Navigate to the **Advanced options**.
3. Check/uncheck the **Enable test automation** checkbox.
4. Confirm changes by clicking the **SUBMIT** button.

## Automation API
All automation requests listed below are sent to the `http://localhost:3000`.
> Note: The API is designed with expectation that replies to the automation requests are sent AFTER the requested operation (e.g. power cycle, user presence) has been concluded.

<br>

| API | Description |
| :------ | :---------- |
| `/conformance/userpresence` | Sent when tools request a user presence confirmation. |
| `/conformance/powercycle` | Sent when tools request a device power cycle. Usually preceeds device reset. <br><br> Blocks test execution and waits for a successful status code (200-299).<br>Other status codes or failure to reply in time are interpreted as failed powercycle.|
| `/conformance/results` | **NOTE: This has no relation to the results submittion after passing conformance tests!**<br><br>Sent when testing has been concluded, `body` contains a JSON with the following information:<br>`allTestsSelected` - Whether all available tests were selected.<br>`passedTestsCount` - How many tests were successfully passed.<br>`failedTestsCount` - How many tests were failed.<br>`failedTests` - An array with brief description of which exact tests were failed. |


## Startup arguments
Conformance tools accept several startup arguments which can be used to further improve the automation experience.

`--autostart` - Automatically launches the last used test configuration upon application launch.

`--prompt-has-display=` `true|false` - If specified, skips user prompt about authenticator display and uses the provided value instead.

`--prompt-u2f-compat=` `true|false` - If specified, skips user prompt about U2F support and uses the provided value instead.
