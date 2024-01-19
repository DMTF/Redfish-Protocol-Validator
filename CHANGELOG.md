# Change Log

## [1.2.2] - 2024-01-19
- Several fixes to 'password change required' testing to ensure 'system under test' parameters are passed correctly

## [1.2.1] - 2024-01-08
- Removed restrictions on urllib3 versions

## [1.2.0] - 2023-10-27
- Version change to fix release assets; no functional changes

## [1.1.9] - 2023-09-15
- Added method to poll tasks for tests using PATCH, POST, and DELETE

## [1.1.8] - 2023-06-23
- Cleanup of TODO notes throughout the tool

## [1.1.7] - 2023-06-16
- Improved password generation for test accounts to inspect min and max password length requirements
- Added 'Allow' header inspection for 'REQ_POST_CREATE_NOT_SUPPORTED' to see if a warning should be used instead of a failure in case the test account creation fails unexpectedly

## [1.1.6] - 2023-02-10
- Updated the expected pattern for the ST header in SSDP responses to allow for multi-digit minor versions

## [1.1.5] - 2023-01-27
- Corrected the USN pattern for SSDP responses to allow for a multi-digit minor version

## [1.1.4] - 2022-11-18
- Tagged the DELETE request to service root as UNSUPPORTED_REQ to better isolate DELETE testing from when it's expected to succeed

## [1.1.3] - 2022-11-07
- Corrected the SSDP request format to add a missing CRLF
- Extended the test for checking that and event subscription is deleted when an SSE stream is closed from 3 seconds to 60 seconds

## [1.1.2] - 2022-07-22
- Minor updates to script packaging

## [1.1.1] - 2022-07-15
- Modified ETag testing to not assume previous ETags are now invalid
- Modified project for PyPI publication

## [1.1.0] - 2022-04-07
- Enabled HTTP tracing when 'log-level' is set to 'DEBUG'
- Added step to enable the newly created user account when testing the password change requirements

## [1.0.9] - 2021-10-15
- Updated media type tests to skip POST responses that do not provide a response body

## [1.0.8] - 2021-10-08
- Corrected HEAD tests to allow for the case where HEAD is not supported
- Corrected PATCH mixed property test to allow for the service to reject the request entirely
- Corrected error response checking for unsupported properties in the PATCH request to allow for the message to be outside of the extended info array

## [1.0.7] - 2021-09-17
- Fixed the array truncate test to allow for 'null' padding in responses
- Changed the minimum array size for several array tests from three to two

## [1.0.6] - 2021-08-13
- Corrected expected status code for SEC_PRIV_OPERATION_TO_PRIV_MAPPING to be 403 or 404

## [1.0.5] - 2021-07-02
- Changed HTTP method for checking Allow header presence on an HTTP 405 response from TRACE to DELETE
- Changed event subscription tests to create subscriptions using IP addresses instead of network names
- Removed message checks for unsupported query parameters

## [1.0.4] - 2021-04-23
- Corrected socket connect() call to use hostname instead of netloc

## [1.0.3] - 2021-04-02
- Made fix to testing an SSE connection is left open after a session is deleted

## [1.0.2] - 2021-02-20
- Fixed bugs in account testing that would cause login failures
- Added exception handling to user account management

## [1.0.1] - 2021-02-15
- Added exception handling around redirect and SSE testing to ensure better error reporting

## [1.0.0] - 2020-11-06
- Added remaining tests for service responses

## [0.9.7] - 2020-10-30
- Added more testing for service responses

## [0.9.6] - 2020-10-19
- Added support for integration with the Redfish Test Framework
- Added more assertions for service request handling

## [0.9.5] - 2020-09-27
- Added assertions for HTTP headers
- Added assertions for query parameters
- Added assertions for modification requests

## [0.9.0] - 2020-07-24
- Initial release
