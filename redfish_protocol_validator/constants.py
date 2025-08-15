# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

from aenum import Enum, auto


SSDP_ALL = 'ssdp:all'
SSDP_REDFISH = 'urn:dmtf-org:service:redfish-rest:1'


class NoValue(Enum):
    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)


class Result(NoValue):
    PASS = 'PASS'
    FAIL = 'FAIL'
    WARN = 'WARN'
    NOT_TESTED = 'NOT-TESTED'


class ResourceType(NoValue):
    MANAGER_ACCOUNT = auto()
    ROLE = auto()


class RequestType(NoValue):
    NORMAL = auto()
    BASIC_AUTH = auto()
    HTTP_BASIC_AUTH = auto()
    NO_AUTH = auto()
    HTTP_NO_AUTH = auto()
    BAD_AUTH = auto()
    PWD_CHANGE_REQUIRED = auto()
    BAD_ETAG = auto()
    MODIFY_OTHER = auto()
    SUBSCRIPTION = auto()
    STREAMING = auto()
    YAML = auto()
    PATCH_MIXED_PROPS = auto()
    PATCH_BAD_PROP = auto()
    PATCH_ODATA_PROPS = auto()
    UNSUPPORTED_REQ = auto()


class Assertion(NoValue):
    # Last sync: 1.20.0
    # See the wiki for 'shall' statements that are not tested

    # Note: Strings follow the format 'CLAUSE: STATEMENT', where 'CLAUSE' is the section heading and 'STATEMENT' is the
    # 'shall' statement from the specification.  Copy the 'shall' language as best as possible.  Modify when the
    # statement is awkward as a standalone sentence in a report.  For example, 'If the Required column contains Yes,
    # a Redfish interface shall support the HTTP method' doesn't tell the user much information about a test failure.

    # 'Protocol details' assertions (prefix of "PROTO_")
    PROTO_URI_SAFE_CHARS = (
        'Universal Resource Identifiers: URIs shall not include any RFC1738-defined unsafe characters.')
    PROTO_URI_NO_ENCODED_CHARS = (
        'Universal Resource Identifiers: URIs shall not include any percent-encoding of characters.')
    PROTO_HTTP_SUPPORTED_METHODS = (
        'HTTP methods: Services shall support the POST, GET, PATCH, and DELETE HTTP methods.')
    PROTO_HTTP_UNSUPPORTED_METHODS = (
        'HTTP methods: Services shall return the HTTP 405 Method Not Allowed status code or the HTTP 501 Not '
        'Implemented status code for unsupported and undocumented methods.')
    PROTO_REDIRECT_ENFORCES_TARGET_PRIVS = (
        'HTTP redirect: The service for the redirected resource shall enforce the authentication and authorization '
        'requirements for the redirected resource.')
    PROTO_JSON_ALL_RESOURCES = (
        'Media types: All resources shall be available through the JSON application/json media type.')
    PROTO_JSON_RFC = (
        'Media types: Services shall make every resource available in a JSON-based representation as a JSON object.')
    PROTO_JSON_ACCEPTED = (
        'Media types: Receivers shall not reject a JSON-encoded message, and shall offer at least one JSON-based '
        'response representation.')
    PROTO_ETAG_ON_GET_ACCOUNT = (
        'ETags: Implementations shall support the return of ETag headers for GET requests of ManagerAccount resources.')
    PROTO_ETAG_RFC7232 = (
        'ETags: If a resource supports an ETag, it shall use the RFC7232-defined ETag.')
    PROTO_STD_URI_SERVICE_ROOT = (
        'Protocol version: The root URI for this version of the Redfish protocol shall be /redfish/v1/.')
    PROTO_STD_URI_VERSION = (
        'Protocol version: A GET operation on the /redfish resource shall return {"v1": "/redfish/v1/"}')
    PROTO_STD_URIS_SUPPORTED = (
        'Redfish-defined URIs and relative reference rules: Services shall support the /redfish, /redfish/v1/, '
        '/redfish/v1/odata, and /redfish/v1/$metadata URIs.')
    PROTO_STD_URI_SERVICE_ROOT_REDIRECT = (
        'Redfish-defined URIs and relative reference rules: Services shall process /redfish/v1 by redirecting it to '
        '/redfish/v1/ or treating it as equivalent to /redfish/v1/')
    PROTO_URI_RELATIVE_REFS = (
        'Redfish-defined URIs and relative reference rules: All relative references shall start with either a double '
        'forward slash (//) with the authority (network-path) or a single forward slash (/) and include the '
        'absolute-path.')

    # 'Service requests' assertions (prefix of "REQ_")
    REQ_HEADERS_ACCEPT = (
        'Request headers: Services shall process the Accept header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_AUTHORIZATION = (
        'Request headers: Services shall process the Authorization header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_CONTENT_TYPE = (
        'Request headers: Services shall process the Content-Type header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_HOST = (
        'Request headers: Services shall process the Host header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_IF_MATCH = (
        'Request headers: Services shall process the If-Match header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_ODATA_VERSION = (
        'Request headers: Services shall process the OData-Version header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_ORIGIN = (
        'Request headers: Services shall process the Origin header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_USER_AGENT = (
        'Request headers: Services shall process the User-Agent header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_HEADERS_X_AUTH_TOKEN = (
        'Request headers: Services shall process the X-Auth-Token header with the behaviors defined in the Redfish '
        'Specification and HTTP 1.1 Specification.')
    REQ_GET_NO_ACCEPT_HEADER = (
        'GET (read requests) overview: If the Accept header is absent, the service shall return the resource\'s '
        'representation as application/json.')
    REQ_GET_IGNORE_BODY = (
        'GET (read requests) overview: Services shall ignore the content of the body on a GET.')
    REQ_GET_COLLECTION_COUNT_PROP_REQUIRED = (
        'Resource collection requests: Retrieved resource collections shall always include the Members@odata.count '
        'property to specify the total number of entries in its Members array.')
    REQ_GET_COLLECTION_COUNT_PROP_TOTAL = (
        'Resource collection requests: Regardless of the Members@odata.nextLink property or paging, the '
        'Members@odata.count property shall return the total number of resources that the Members array references.')
    REQ_GET_SERVICE_ROOT_URL = (
        'Service root request: The root URL for Redfish version 1.x services shall be /redfish/v1/.')
    REQ_GET_SERVICE_ROOT_NO_AUTH = (
        'Service root request: Services shall not require authentication to retrieve the service root and /redfish '
        'resources.')
    REQ_GET_METADATA_URI = (
        'OData service and metadata document requests: Services shall expose an OData metadata document at the '
        '/redfish/v1/$metadata URI.')
    REQ_GET_ODATA_URI = (
        'OData service and metadata document requests: Services shall expose an OData service document at the '
        '/redfish/v1/odata URI')
    REQ_GET_METADATA_ODATA_NO_AUTH = (
        'OData service and metadata document requests: Services shall not require authentication to retrieve the OData '
        'metadata document or the OData service document.')
    REQ_QUERY_PROTOCOL_FEATURES_SUPPORTED = (
        'Query parameter overview: Services shall include the ProtocolFeaturesSupported object in the service root, if '
        'the service support query parameters.')
    REQ_QUERY_IGNORE_UNSUPPORTED = (
        'Query parameter overview: Services shall ignore unknown or unsupported query parameters that do not begin '
        'with $.')
    REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS = (
        'Query parameter overview: Services shall return the HTTP 501 Not Implemented status code for any unsupported '
        'query parameters that start with $.')
    REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR = (
        'Query parameter overview: Services shall return an extended error that indicates the unsupported query '
        'parameters for this resource.')
    REQ_QUERY_INVALID_VALUES = (
        'Query parameter overview: Services shall return the HTTP 400 Bad Request status code for any query '
        'parameters that contain values that are invalid, or values applied to query parameters without defined '
        'values, such as excerpt or only.')
    REQ_HEAD_DIFFERS_FROM_GET = (
        'HEAD: The HEAD method differs from the GET method in that it shall not return message body information.')
    REQ_DATA_MOD_NOT_SUPPORTED = (
        'Modification error responses: If the resource exists but does not support the requested operation, services '
        'shall return the HTTP 405 Method Not Allowed status code.')
    REQ_DATA_MOD_ERRORS = (
        'Modification error responses: If the service returns a client 4XX or service 5XX status code, the service '
        'encountered an error and the resource shall not have been modified or created as a result of the operation.')
    REQ_PATCH_MIXED_PROPS = (
        'PATCH (update): In cases where at least one property updated successfully, but one or more properties could '
        'not be updated, the service shall return the HTTP 200 OK status code and a resource representation with '
        'extended information that lists the properties that could not be updated.')
    REQ_PATCH_BAD_PROP = (
        'PATCH (update): If all properties in the update request are read-only, unknown, or unsupported, but the '
        'resource can be updated, the service shall return the HTTP 400 Bad Request status code and an error response '
        'with messages that show the non-updatable properties.')
    REQ_PATCH_ODATA_PROPS = (
        'PATCH (update): If the update request only contains OData annotations, the service shall return the HTTP 400 '
        'Bad Request status code with the NoOperation message from the Base Message Registry or a modification success '
        'response.')
    REQ_PATCH_ARRAY_ELEMENT_REMOVE = (
        'PATCH on array properties: The service shall accept null to remove an element.')
    REQ_PATCH_ARRAY_ELEMENT_UNCHANGED = (
        'PATCH on array properties: The service shall accept an empty object {} to leave an element unchanged.')
    REQ_PATCH_ARRAY_OPERATIONS_ORDER = (
        'PATCH on array properties: The order of operations shall be modifications, then deletions, then additions.')
    REQ_PATCH_ARRAY_TRUNCATE = (
        'PATCH on array properties: A request with fewer elements than in the current array shall remove the remaining '
        'elements of the array.')
    REQ_POST_CREATE_VIA_COLLECTION = (
        'POST (create): To create a resource, services shall support the POST method on resource collections.')
    REQ_POST_CREATE_URI_IN_LOCATION_HDR = (
        'POST (create): Services shall set the Location header in the response to the URI of the new resource.')
    REQ_POST_CREATE_TO_MEMBERS_PROP = (
        'POST (create): Submitting a POST request to a resource collection is equivalent to submitting the same '
        'request to the Members property of that resource collection. Services that support the addition of Members to '
        'a resource collection shall support both forms.')
    REQ_POST_CREATE_NOT_IDEMPOTENT = (
        'POST (create): The POST operation shall not be idempotent.')
    REQ_DELETE_METHOD_REQUIRED = (
        'DELETE (delete): To remove a resource, the service shall support the DELETE method.')

    # 'Service responses' assertions (prefix of "RESP_")
    RESP_HEADERS_ACCESS_CONTROL_ALLOW_ORIGIN = (
        'Response headers: Services shall return the Access-Control-Allow-Origin header with the behaviors defined in '
        'the Redfish Specification and HTTP 1.1 Specification.')
    RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED = (
        'Response headers: Services shall return the Allow header with the HTTP 405 Method Not Allowed status code to '
        'indicate the valid methods for the URI.')
    RESP_HEADERS_ALLOW_GET_OR_HEAD = (
        'Response headers: Services shall return the Allow header for any GET or HEAD operation to indicate the valid '
        'methods for the URI.')
    RESP_HEADERS_CACHE_CONTROL = (
        'Response headers: Services shall return the Cache-Control header.')
    RESP_HEADERS_CONTENT_TYPE = (
        'Response headers: Services shall return the Content-Type header.')
    RESP_HEADERS_ETAG = (
        'Response headers: Services shall return the ETag header for all GET operations on ManagerAccount resources.')
    RESP_HEADERS_LINK_REL_DESCRIBED_BY = (
        'Link header: Services shall return the Link header containing rel=describedby on GET and HEAD requests.')
    RESP_HEADERS_LINK_SCHEMA_VER_MATCH = (
        'Link header: If the referenced JSON Schema is a versioned schema, it shall match the version contained in the '
        'value of the @odata.type property returned in the resource.')
    RESP_HEADERS_LOCATION = (
        'Response headers: Service shall return the Location header upon creation of a resource. Location and '
        'X-Auth-Token shall be included on responses that create user sessions.')
    RESP_HEADERS_ODATA_VERSION = (
        'Response headers: Services shall return the OData-Version header.')
    RESP_HEADERS_WWW_AUTHENTICATE = (
        'Response headers: Services shall return the WWW-Authenticate header when authentication headers in the '
        'request are missing or invalid.')
    RESP_HEADERS_X_AUTH_TOKEN = (
        'Response headers: The token value from the X-Auth-Token header shall be indistinguishable from random.')
    RESP_STATUS_BAD_REQUEST = (
        'Status codes: The response body for 400 Bad Request status code responses shall contain extended error '
        'information.')
    RESP_STATUS_INTERNAL_SERVER_ERROR = (
        'Status codes: The response body for 500 Internal Server Error status code responses shall contain extended '
        'error information.')
    RESP_ODATA_METADATA_MIME_TYPE = (
        'OData $metadata: Service shall use the application/xml or application/xml;charset=utf-8 MIME types to return '
        'the OData metadata document as an XML document.')
    RESP_ODATA_METADATA_ENTITY_CONTAINER = (
        'Referencing other schemas: The service\'s OData metadata document shall include an EntityContainer that '
        'defines the top-level resources and resource collections.')
    RESP_ODATA_SERVICE_MIME_TYPE = (
        'OData service document: Service shall use the application/json MIME type to return the OData service document '
        'as a JSON object.')
    RESP_ODATA_SERVICE_CONTEXT = (
        'OData service document: The JSON object shall contain the @odata.context context property set to '
        '/redfish/v1/$metadata .')
    RESP_ODATA_SERVICE_VALUE_PROP = (
        'OData service document: The JSON object shall include a value property set to a JSON array that contains an '
        'entry for the service root and each resource that is a direct child of the service root.')

    # 'Service details' assertions (prefix of "SERV_")
    SERV_EVENT_POST_RESP = (
        'POST to subscription collection: If subscription request succeeds, the service shall return an HTTP 201 '
        'Created status code, and the Location header that contains a URI of the newly created subscription resource.')
    SERV_EVENT_ERROR_ON_BAD_REQUEST = (
        'POST to subscription collection: Services shall respond to a request to create a subscription with an error '
        'if the body of the request is conflicting.')
    SERV_SSDP_CAN_BE_DISABLED = (
        'Discovery overview: SSDP, if implemented, shall enable the user to disable the protocol through the '
        'ManagerNetworkProtocol resource.')
    SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID = (
        'USN format: The UUID in the USN field of the service shall equal the UUID property in the service root.')
    SERV_SSDP_UUID_STATIC = (
        'USN format: If multiple or redundant managers exist, the UUID of the service shall remain static regardless '
        'of redundancy failover.')
    SERV_SSDP_UUID_IN_CANONICAL_FORMAT = (
        'USN format: The unique ID shall be in the canonical UUID format, followed by ::dmtf-org.')
    SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL = (
        'M-SEARCH response: Services shall respond to M-SEARCH queries for Search Target (ST) of the Redfish Service, '
        'as well as ssdp:all.')
    SERV_SSDP_ST_HEADER_FORMAT = (
        'M-SEARCH response: The URN provided in the ST header in the reply shall use the redfish-rest: service name '
        'followed by the major version of the Redfish Specification. If the minor version of the Redfish Specification '
        'to which the service conforms is a non-zero value, the service may append the minor version with a preceding '
        'colon (:).')
    SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT = (
        'M-SEARCH response: Services shall provide clients with the AL header that points to the Redfish service root '
        'URL.')
    SERV_SSDP_M_SEARCH_RESPONSE_FORMAT = (
        'M-SEARCH response: The response to an M-SEARCH multicast or unicast query shall use the format defined in the '
        'Redfish Specification.')
    SERV_SSE_SUCCESSFUL_RESPONSE = (
        'Server-sent events: Successful resource responses for SSE shall return the HTTP 200 OK status code and have a '
        'Content-Type header set as text/event-stream or text/event-stream;charset=utf-8.')
    SERV_SSE_UNSUCCESSFUL_RESPONSE = (
        'Server-sent events: Unsuccessful resource responses for SSE shall return an HTTP status code of 400 or '
        'greater, have a Content-Type header set as application/json or application/json;charset=utf-8, and contain a '
        'JSON object in the response body, as described in Error responses, which details the error or errors.')
    SERV_SSE_BLANK_LINES_BETWEEN_EVENTS = (
        'Server-sent events: Services shall separate events with blank lines. ')
    SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED = (
        'Server-sent events: If a client performs a GET on the URI specified by the ServerSentEventUri property, the '
        'service shall keep the connection open and conform to the HTML5 Specification until the client closes the '
        'socket.')
    SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION = (
        'Server-sent events: Service-generated events shall be sent to the client by using the open connection.')
    SERV_SSE_OPEN_CREATES_EVENT_DEST = (
        'Server-sent events: When a client opens an SSE stream for the event aervice, the service shall create an '
        'EventDestination resource in the subscriptions collection for the event service to represent the connection.')
    SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR = (
        'Server-sent events: The Context property in the EventDestination resource shall be a service-generated opaque '
        'string.')
    SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE = (
        'Server-sent events: The service shall delete the corresponding EventDestination resource when the connection '
        'is closed.')
    SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED = (
        'Server-sent events: The service shall close the connection if the corresponding EventDestination resource is '
        'deleted.')
    SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD = (
        'Server-sent events: The service shall use the id field in the SSE stream to uniquely identify a payload in '
        'the SSE stream.')
    SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT = (
        'Server-sent events: The service shall use the data field in the SSE stream based on the payload format. The '
        'SSE streams have these formats: metric report SSE stream and event message SSE stream.')
    SERV_SSE_JSON_EVENT_MESSAGE_FORMAT = (
        'Server-sent events: The service shall use the data field in the SSE stream to include the JSON representation '
        'of the event object.')
    SERV_SSE_JSON_METRIC_REPORT_FORMAT = (
        'Server-sent events: The service shall use the data field in the SSE stream to include the JSON representation '
        'of the MetricReport object.')

    # 'Security details' assertions (prefix of "SEC_")
    SEC_TLS_1_1 = (
        'Transport Layer Security (TLS) protocol overview: Implementations shall support the Transport Layer Security '
        '(TLS) protocol v1.1 or later.')
    SEC_DEFAULT_CERT_REPLACE = (
        'Certificates: Implementations shall support replacement of the default certificate if one is provided.')
    SEC_CERTS_CONFORM_X509V3 = (
        'Certificates: Implementations shall use certificates that conform to X.509-v3, as defined in RFC5280.')
    SEC_BOTH_AUTH_TYPES = (
        'Authentication overview: Services shall support both "Basic authentication" and "Redfish session login '
        'authentication".')
    SEC_BASIC_AUTH_STANDALONE = (
        'Authentication overview: Services shall not require a client that uses HTTP Basic authentication to create a '
        'session.')
    SEC_WRITE_REQUIRES_AUTH = (
        'Resource and operation authentication requirements: Services shall authenticate all write requests to Redfish '
        'resources, with some exceptions.')
    SEC_READ_REQUIRES_AUTH = (
        'Resource and operation authentication requirements: Resources shall not be available as unauthenticated, with '
        'some exceptions.')
    SEC_HEADERS_FIRST = (
        'HTTP header authentication requirements: Services shall process HTTP headers for authentication before other '
        'headers that may affect the response.')
    SEC_NO_AUTH_COOKIES = (
        'HTTP header authentication requirements: Services shall not use HTTP cookies to authenticate any activity.')
    SEC_NO_PRIV_INFO_IN_MSGS = (
        'Authentication failure requirements: When authentication fails, extended error messages shall not provide '
        'privileged information.')
    SEC_SUPPORT_BASIC_AUTH = (
        'HTTP Basic authentication: Services shall support HTTP Basic authentication and shall use only connections '
        'that conform to TLS to transport the data between any third-party authentication service and clients.')
    SEC_BASIC_AUTH_OVER_HTTPS = (
        'HTTP Basic authentication: All requests that use HTTP Basic authentication shall require HTTPS.')
    SEC_REQUIRE_LOGIN_SESSIONS = (
        'Redfish session login authentication: Service shall provide login sessions that conform with this '
        'specification.')
    SEC_SESSIONS_URI_LOCATION = (
        'Redfish login sessions: The session service\'s Sessions property and the service root\'s Sessions property in '
        'Links property shall contain the same URI.')
    SEC_SESSION_CREATE_HTTPS_ONLY = (
        'Session login: The POST to create a session shall only be supported with HTTPS.')
    SEC_SESSION_POST_RESPONSE = (
        'Session login: The response to the POST request to create a session shall include the X-Auth-Token header, '
        'the Location header, and a JSON body containing the full representation of the new session resource.')
    SEC_SESSION_TERMINATION_SIDE_EFFECTS = (
        'Session termination or logout: When a session is terminated, the service shall not affect independent '
        'connections established originally by this session for other purposes.')
    SEC_PRIV_ONE_ROLE_PRE_USER = (
        'Privilege model: Each user shall be assigned exactly one role.')
    SEC_PRIV_SUPPORT_PREDEFINED_ROLES = (
        'Roles: Services shall support the Administrator, Operator, and ReadOnly standard roles.')
    SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE = (
        'Roles: The AssignedPrivileges property in the Role resource for standard roles shall not be modifiable.')
    SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE = (
        'Privilege model: A role shall be assigned to a user when a manager account is created.')
    SEC_PRIV_OPERATION_TO_PRIV_MAPPING = (
        'Redfish service operation-to-privilege mapping: For every request that a client makes to a service, the '
        'service shall determine that the authenticated identity of the requester has the authorization to complete '
        'the requested operation on the resource in the request.')
    SEC_ACCOUNTS_SUPPORT_ETAGS = (
        'Account service overview: User accounts shall support ETags and atomic operations.')
    SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN = (
        'Password change required handling: When using an account with PasswordChangeRequired set to true, the service '
        'shall allow a session login and include a @Message.ExtendedInfo object in the response containing the '
        'PasswordChangeRequired message from the Base Message Registry.')
    SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT = (
        'Password change required handling: When using an account with PasswordChangeRequired set to true, the service '
        'shall allow a GET operation on the ManagerAccount resource associated with the account.')
    SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD = (
        'Password change required handling: When using an account with PasswordChangeRequired set to true, the service '
        'shall allow a PATCH operation on the ManagerAccount resource associated with the account to update the '
        'Password property. If the value of Password is changed, the service shall also set the PasswordChangeRequired '
        'property to false.')
    SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS = (
        'Password change required handling: For all other operations when using an account with PasswordChangeRequired '
        'set to true, the service shall respond with the HTTP 403 Forbidden status code and include a '
        '@Message.ExtendedInfo object that contains the PasswordChangeRequired message from the Base Message Registry.')
