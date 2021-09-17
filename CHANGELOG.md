# Change Log

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
