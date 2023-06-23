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
    PATCH_RO_RESOURCE = auto()
    PATCH_COLLECTION = auto()
    PATCH_ODATA_PROPS = auto()
    UNSUPPORTED_REQ = auto()


class Assertion(NoValue):
    # Protocol details assertions (prefix of "PROTO_")
    PROTO_URI_SAFE_CHARS = (
        'URIs shall not include any RFC1738-defined unsafe characters.')
    PROTO_URI_NO_ENCODED_CHARS = (
        'URIs shall not include any percent-encoding of characters.')
    PROTO_HTTP_SUPPORTED_METHODS = (
        'HTTP methods POST, GET, PATCH, and DELETE shall be supported.')
    PROTO_HTTP_UNSUPPORTED_METHODS = (
        'For HTTP methods that the Redfish service does not support or that '
        'the following table omits, the Redfish service shall return the HTTP '
        '405 Method Not Allowed status code or the HTTP 501 Not Implemented '
        'status code.')
    PROTO_JSON_ALL_RESOURCES = (
        'All resources shall be available through the JSON application/json '
        'media type.')
    PROTO_JSON_RFC = (
        'Redfish Services shall make every resource available in a JSON-based '
        'representation, as specified in RFC4627')
    PROTO_JSON_ACCEPTED = (
        'Receivers shall not reject a JSON-encoded message, and shall offer '
        'at least one JSON-based response representation.')
    PROTO_ETAG_ON_GET_ACCOUNT = (
        'Implementations shall support the return of ETag headers for GET '
        'requests of ManagerAccount resources.')
    PROTO_ETAG_RFC7232 = (
        'If a resource supports an ETag, it shall use the RFC7232-defined '
        'ETag.')
    PROTO_STD_URI_SERVICE_ROOT = (
        'The root URI for this version of the Redfish protocol shall be '
        '/redfish/v1/.')
    PROTO_STD_URI_VERSION = (
        'A GET operation on the /redfish resource shall return this response '
        'body: {"v1": "/redfish/v1/"}')
    PROTO_STD_URIS_SUPPORTED = (
        'A Redfish Service shall support these Redfish-defined URIs: '
        '/redfish, /redfish/v1/, /redfish/v1/odata, /redfish/v1/$metadata')
    PROTO_STD_URI_SERVICE_ROOT_REDIRECT = (
        'The service shall process the [/redfish/v1] URI without a trailing '
        'slash in one of these ways: Redirect it to the associated '
        'Redfish-defined URI, or treat it as the equivalent URI to the '
        'associated Redfish-defined URI (/redfish/v1/).')
    PROTO_URI_RELATIVE_REFS = (
        'All relative references (see RFC3986) that the service uses shall '
        'start with either: A double forward slash (//) and include the '
        'authority (network-path), such as '
        '//mgmt.vendor.com/redfish/v1/Systems, or a single forward slash (/) '
        'and include the absolute-path, such as /redfish/v1/Systems.')
    # Service requests assertions (prefix of "REQ_")
    REQ_HEADERS_ACCEPT = (
        'Redfish Services shall process the [Accept header] in the following '
        'table as defined by the HTTP 1.1 specification if the value in the '
        'Service Requirement column is set to "Yes", or if the value is '
        '"Conditional" under the conditions noted in the Description column.'
    )
    REQ_HEADERS_AUTHORIZATION = (
        'Redfish Services shall process the [Authorization header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_HEADERS_CONTENT_TYPE = (
        'Redfish Services shall process the [Content-Type header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_HEADERS_HOST = (
        'Redfish Services shall process the [Host header] in the following '
        'table as defined by the HTTP 1.1 specification if the value in the '
        'Service Requirement column is set to "Yes", or if the value is '
        '"Conditional" under the conditions noted in the Description column.'
    )
    REQ_HEADERS_IF_MATCH = (
        'Redfish Services shall process the [If-Match header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_HEADERS_ODATA_VERSION = (
        'Redfish Services shall process the [OData-Version header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_HEADERS_ORIGIN = (
        'Redfish Services shall process the [Origin header] in the following '
        'table as defined by the HTTP 1.1 specification if the value in the '
        'Service Requirement column is set to "Yes", or if the value is '
        '"Conditional" under the conditions noted in the Description column.'
    )
    REQ_HEADERS_USER_AGENT = (
        'Redfish Services shall process the [User-Agent header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_HEADERS_X_AUTH_TOKEN = (
        'Redfish Services shall process the [X-Auth-Token header] in the '
        'following table as defined by the HTTP 1.1 specification if the '
        'value in the Service Requirement column is set to "Yes", or if the '
        'value is "Conditional" under the conditions noted in the Description '
        'column.'
    )
    REQ_GET_NO_ACCEPT_HEADER = (
        'If the Accept header is absent, the service shall return the '
        'resource\'s representation as application/json.'
    )
    REQ_GET_IGNORE_BODY = (
        'The service shall ignore the content of the body on a GET.'
    )
    REQ_GET_COLLECTION_COUNT_PROP_REQUIRED = (
        'Retrieved resource collections shall always include the count '
        'property to specify the total number of entries in its Members array.'
    )
    REQ_GET_COLLECTION_COUNT_PROP_TOTAL = (
        'Regardless of the next link property or paging, the count property '
        'shall return the total number of resources that the Members array '
        'references.'
    )
    REQ_GET_SERVICE_ROOT_URL = (
        'The root URL for Redfish version 1.x services shall be /redfish/v1/.'
    )
    REQ_GET_SERVICE_ROOT_NO_AUTH = (
        'Services shall not require authentication to retrieve the Service '
        'Root and /redfish resources.'
    )
    REQ_GET_METADATA_URI = (
        'Service shall expose an OData metadata document at the '
        '/redfish/v1/$metadata URI.'
    )
    REQ_GET_ODATA_URI = (
        'Service shall expose an OData service document at the '
        '/redfish/v1/odata URI.'
    )
    REQ_GET_METADATA_ODATA_NO_AUTH = (
        'Service shall not require authentication to retrieve the OData '
        'metadata document or the OData service document.'
    )
    REQ_QUERY_PROTOCOL_FEATURES_SUPPORTED = (
        'Services shall include the ProtocolFeaturesSupported object in the '
        'Service Root, if the service supports query parameters.'
    )
    REQ_QUERY_IGNORE_UNSUPPORTED = (
        'Services shall ignore unknown or unsupported query parameters that '
        'do not begin with $.'
    )
    REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS = (
        'Services shall return the HTTP 501 Not Implemented status code for '
        'any unsupported query parameters that start with $.'
    )
    REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR = (
        'Services shall return an extended error that indicates the '
        'unsupported query parameters for this resource.'
    )
    REQ_QUERY_INVALID_VALUES = (
        'Services shall return the HTTP 400 Bad Request status code for any '
        'query parameters that contain values that are invalid, or values '
        'applied to query parameters without defined values, such as excerpt '
        'or only.'
    )
    REQ_HEAD_DIFFERS_FROM_GET = (
        'The HEAD method differs from the GET method in that it shall not '
        'return message body information.'
    )
    REQ_DATA_MOD_ERRORS = (
        'Otherwise, if the service returns a client 4XX or service 5XX status '
        'code, the service encountered an error and the resource shall not '
        'have been modified or created as a result of the operation.'
    )
    REQ_PATCH_MIXED_PROPS = (
        'A partial success of a PATCH operation occurs when a modification '
        'request for multiple properties results in at least one property '
        'updated successfully, but one or more properties could not be '
        'updated. In these cases, the service shall return the HTTP 200 OK '
        'status code and a resource representation with extended information '
        'that lists the properties that could not be updated.  The '
        'implementation may reject the update on certain properties based on '
        'its own policies and, in this case, not make the requested update.'
    )
    REQ_PATCH_BAD_PROP = (
        'If all properties in the update request are read-only, unknown, or '
        'unsupported, but the resource can be updated, the service shall '
        'return the HTTP 400 Bad Request status code and an error response '
        'with messages that show the non-updatable properties.'
    )
    REQ_PATCH_RO_RESOURCE = (
        'Modify a resource or all properties that can never be updated: '
        'Services shall return the HTTP 405 status code.'
    )
    REQ_PATCH_COLLECTION = (
        'A client PATCH request against a resource collection: Services shall '
        'return the HTTP 405 status code.'
    )
    REQ_PATCH_ODATA_PROPS = (
        'A client only provides OData annotations: Services shall return the '
        'HTTP 400 Bad Request status code with the NoOperation message from '
        'the Base Message Registry or one of the modification success '
        'responses.'
    )
    REQ_PATCH_ARRAY_ELEMENT_REMOVE = (
        'Within a PATCH request, the service shall accept null to remove an '
        'element.'
    )
    REQ_PATCH_ARRAY_ELEMENT_UNCHANGED = (
        'Within a PATCH request, the service shall accept an empty object {} '
        'to leave an element unchanged'
    )
    REQ_PATCH_ARRAY_OPERATIONS_ORDER = (
        'When processing a PATCH request, the order of operations shall be: '
        'modifications, deletions, additions.'
    )
    REQ_PATCH_ARRAY_TRUNCATE = (
        'A PATCH request with fewer elements than in the current array shall '
        'remove the remaining elements of the array.'
    )
    REQ_PUT_NOT_IMPLEMENTED = (
        'If a service does not implement this method, the service shall '
        'return the HTTP 405 Method Not Allowed status code.'
    )
    REQ_POST_CREATE_VIA_COLLECTION = (
        'To create a resource, services shall support the POST method on '
        'resource collections.'
    )
    REQ_POST_CREATE_URI_IN_LOCATION_HDR = (
        'Additionally, the service shall set the Location header in the '
        'response to the URI of the new resource.'
    )
    REQ_POST_CREATE_TO_MEMBERS_PROP = (
        'Submitting a POST request to a resource collection is equivalent to '
        'submitting the same request to the Members property of that resource '
        'collection. Services that support the addition of Members to a '
        'resource collection shall support both forms.'
    )
    REQ_POST_CREATE_NOT_SUPPORTED = (
        'If the service does not enable creation of resources, the service '
        'shall return the HTTP 405 Method Not Allowed status code.'
    )
    REQ_POST_CREATE_NOT_IDEMPOTENT = (
        'The POST operation shall not be idempotent.'
    )
    REQ_DELETE_METHOD_REQUIRED = (
        'To remove a resource, the service shall support the DELETE method.'
    )
    REQ_DELETE_NON_DELETABLE_RESOURCE = (
        'If the resource can never be deleted, the service shall return the '
        'HTTP 405 Method Not Allowed status code.'
    )
    # Service responses assertions (prefix of "RESP_")
    RESP_HEADERS_ACCESS_CONTROL_ALLOW_ORIGIN = (
        'Redfish Services shall return the HTTP 1.1 Specification-defined '
        '[Access-Control-Allow-Origin header] if the value in the Required '
        'column is Yes.'
    )
    RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED = (
        '[The Allow header] shall be returned with the HTTP 405 (Method Not '
        'Allowed) status code to indicate the valid methods for the request '
        'URI.'
    )
    RESP_HEADERS_ALLOW_GET_OR_HEAD = (
        '[The Allow header] shall be returned with any GET or HEAD operation '
        'to indicate the other allowable operations for this resource.'
    )
    RESP_HEADERS_CACHE_CONTROL = (
        'Redfish Services shall return the HTTP 1.1 Specification-defined '
        '[Cache-Control header] if the value in the Required column is Yes.'
    )
    RESP_HEADERS_CONTENT_TYPE = (
        'Redfish Services shall return the HTTP 1.1 Specification-defined '
        '[Content-Type header] if the value in the Required column is Yes.'
    )
    RESP_HEADERS_ETAG = (
        'The ETag header shall be included on responses to GETs of '
        'ManagerAccount resources.'
    )
    RESP_HEADERS_LINK_REL_DESCRIBED_BY = (
        'A Link header containing rel=describedby shall be returned on GET '
        'and HEAD requests.'
    )
    RESP_HEADERS_LINK_SCHEMA_VER_MATCH = (
        'If the referenced JSON Schema is a versioned schema, it shall match '
        'the version contained in the value of the @odata.type property '
        'returned in this resource.'
    )
    RESP_HEADERS_LOCATION = (
        '[The Location header] shall be returned upon creation of a resource. '
        'Location and X-Auth-Token shall be included on responses that create '
        'user sessions.'
    )
    RESP_HEADERS_ODATA_VERSION = (
        'Redfish Services shall return the HTTP 1.1 Specification-defined '
        '[OData-Version header] if the value in the Required column is Yes.'
    )
    RESP_HEADERS_WWW_AUTHENTICATE = (
        'Redfish Services shall return the HTTP 1.1 Specification-defined '
        '[WWW-Authenticate header] if the value in the Required column is Yes.'
    )
    RESP_HEADERS_X_AUTH_TOKEN = (
        'The token value [from the X-Auth-Token header] shall be '
        'indistinguishable from random.'
    )
    RESP_STATUS_BAD_REQUEST = (
        '[In a 400 Bad Request response] the response body shall return an '
        'extended error as defined in the Error responses clause.'
    )
    RESP_STATUS_INTERNAL_SERVER_ERROR = (
        '[In a 500 Internal Server Error response] the response body shall '
        'return an extended error as defined in the Error responses clause.'
    )
    RESP_ODATA_METADATA_MIME_TYPE = (
        'The service shall use the application/xml or '
        'application/xml;charset=utf-8 MIME types to return the OData '
        'metadata document as an XML document.'
    )
    RESP_ODATA_METADATA_ENTITY_CONTAINER = (
        'The service\'s OData metadata document shall include an '
        'EntityContainer that defines the top-level resources and resource '
        'collections.'
    )
    RESP_ODATA_SERVICE_MIME_TYPE = (
        'The service shall use the application/json MIME type to return the '
        'OData service document as a JSON object.'
    )
    RESP_ODATA_SERVICE_CONTEXT = (
        'The JSON object shall contain the @odata.context context property '
        'set to /redfish/v1/$metadata .'
    )
    RESP_ODATA_SERVICE_VALUE_PROP = (
        'The JSON object shall include a value property set to a JSON array '
        'that contains an entry for the Service Root and each resource that '
        'is a direct child of the Service Root.'
    )
    # Service details assertions (prefix of "SERV_")
    SERV_EVENT_POST_RESP = (
        'If the [Event Service] subscription request succeeds, the service '
        'shall return an HTTP 201 Created status code, and the Location '
        'header that contains a URI of the newly created subscription '
        'resource.'
    )
    SERV_EVENT_PUSH_STYLE = (
        'Services shall support push style eventing for all resources that '
        'can send events.'
    )
    SERV_EVENT_ERROR_ON_BAD_REQUEST = (
        'Services shall respond to a request to create a subscription with an '
        'error if the body of the request is conflicting.'
    )
    SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS = (
        'Services shall respond to a request to create a subscription with an '
        'error if the body of the request contains both RegistryPrefixes and '
        'MessageIds, and shall return the HTTP 400 Bad Request status code.'
    )
    SERV_SSDP_CAN_BE_DISABLED = (
        'Use of SSDP is optional, and if implemented, shall enable the user '
        'to disable the protocol through the ManagerNetworkProtocol resource.'
    )
    SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID = (
        'The UUID in the USN field of the service shall equal the UUID '
        'property in the Service Root.'
    )
    # NOTE(bdodd): Testing this failover assertion is probably not practical
    SERV_SSDP_UUID_STATIC = (
        'If multiple or redundant managers exist, the UUID of the service '
        'shall remain static regardless of redundancy failover.'
    )
    SERV_SSDP_UUID_IN_CANONICAL_FORMAT = (
        'The unique ID shall be in the canonical UUID format, followed by '
        '::dmtf-org.'
    )
    SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL = (
        'The managed device shall respond to M-SEARCH queries for Search '
        'Target (ST) of the Redfish Service, as well as ssdp:all.'
    )
    SERV_SSDP_ST_HEADER_FORMAT = (
        'The URN provided in the ST header in the reply shall use the '
        'redfish-rest: service name followed by the major version of the '
        'Redfish Specification. If the minor version of the Redfish '
        'Specification to which the service conforms is a non-zero value, '
        'that minor version shall be appended with and preceded by a colon '
        '(:).'
    )
    SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT = (
        'The managed device shall provide clients with the AL header that '
        'points to the Redfish Service Root URL.'
    )
    SERV_SSDP_M_SEARCH_RESPONSE_FORMAT = (
        'The response to an M-SEARCH multicast or unicast query shall use '
        'the [example format shown].'
    )
    SERV_SSE_SUCCESSFUL_RESPONSE = (
        'Successful resource responses for SSE shall return the HTTP 200 OK '
        'status code and have a Content-Type header set as '
        '"text/event-stream" or "text/event-stream;charset=utf-8".'
    )
    SERV_SSE_UNSUCCESSFUL_RESPONSE = (
        'Unsuccessful resource responses for SSE shall return an HTTP status '
        'code of 400 or greater, have a Content-Type header set as '
        '"application/json" or "application/json;charset=utf-8", and contain '
        'a JSON object in the response body, as described in Error responses, '
        'which details the error or errors.'
    )
    SERV_SSE_BLANK_LINES_BETWEEN_EVENTS = (
        'Services shall separate events with blank lines. '
    )
    SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED = (
        'If a client performs a GET on the URI specified by the '
        'ServerSentEventUri property, the service shall keep the connection '
        'open and conform to the HTML5 Specification until the client closes '
        'the socket.'
    )
    SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION = (
        'Service-generated events shall be sent to the client by using the '
        'open connection.'
    )
    SERV_SSE_OPEN_CREATES_EVENT_DEST = (
        'When a client opens an SSE stream for the Event Service, the service '
        'shall create an EventDestination resource in the Subscriptions '
        'collection for the Event Service to represent the connection.'
    )
    SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR = (
        'The Context property in the EventDestination resource shall be a '
        'service-generated opaque string.'
    )
    SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE = (
        'The service shall delete the corresponding EventDestination resource '
        'when the connection is closed.'
    )
    SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED = (
        'The service shall close the connection if the corresponding '
        'EventDestination resource is deleted.'
    )
    SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD = (
        'The service shall use the id field in the SSE stream to uniquely '
        'identify a payload in the SSE stream.'
    )
    SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT = (
        'The service shall use the data field in the SSE stream based on the '
        'payload format. The SSE streams have these formats: [metric report '
        'SSE stream and event message SSE stream].'
    )
    SERV_SSE_JSON_EVENT_MESSAGE_FORMAT = (
        'The service shall use the data field in the SSE stream to include '
        'the JSON representation of the Event object.'
    )
    SERV_SSE_JSON_METRIC_REPORT_FORMAT = (
        'The service shall use the data field in the SSE stream to include '
        'the JSON representation of the MetricReport object.'
    )
    # Security details assertions (prefix of "SEC_")
    SEC_TLS_1_1 = (
        'Implementations shall support the Transport Layer Security (TLS) '
        'protocol v1.1 or later.'
    )
    SEC_DEFAULT_CERT_REPLACE = (
        'Redfish implementations shall support replacement of the default '
        'certificate if one is provided.'
    )
    SEC_CERTS_CONFORM_X509V3 = (
        'Redfish implementations shall use certificates that conform to '
        'X.509-v3, as defined in RFC5280.'
    )
    SEC_BOTH_AUTH_TYPES = (
        'Service shall support both "Basic authentication" and "Redfish '
        'session login authentication" (as described below under Session '
        'Management).'
    )
    SEC_BASIC_AUTH_STANDALONE = (
        'Services shall not require a client that uses HTTP Basic '
        'authentication to create a session.'
    )
    SEC_WRITE_REQUIRES_AUTH = (
        'Services shall authenticate all write requests to Redfish resources '
        '[except for the POST operation to the Sessions resource collection '
        'for authentication.]'
    )
    SEC_READ_REQUIRES_AUTH = (
        'Redfish resources shall not be available as unauthenticated, except '
        'for [the service root, $metadata document, OData service document, '
        'OpenAPI YAML document, and version object].'
    )
    SEC_REDIRECT_ENFORCES_TARGET_PRIVS = (
        'An HTTP redirect shall enforce the privilege requirements for the '
        'target resource.'
    )
    SEC_REDIRECT_TO_HTTPS = (
        'Generally, if the location is reachable without authentication but '
        'only over HTTPS, the service shall issue a redirect to the HTTPS '
        'version of the resource.'
    )
    SEC_NO_PRIV_INFO_IN_MSGS = (
        'When authentication fails, extended error messages shall not provide '
        'privileged information.'
    )
    SEC_HEADERS_FIRST = (
        'Services shall process HTTP headers for authentication before other '
        'headers that may affect the response. [e.g., ETag, If-Modified, etc.]'
    )
    SEC_NO_AUTH_COOKIES = (
        'Services shall not use HTTP cookies to authenticate any activity, '
        'such as GET, POST, PUT, PATCH, and DELETE.'
    )
    SEC_SUPPORT_BASIC_AUTH = (
        # Note: Second half of this clause is not testable
        'Services shall support HTTP Basic authentication, as defined by '
        'RFC7617, and shall use only connections that conform to TLS to '
        'transport the data between any third-party authentication service '
        'and clients.'
    )
    SEC_BASIC_AUTH_OVER_HTTPS = (
        'All requests that use HTTP Basic authentication shall require HTTPS.'
    )
    SEC_REQUIRE_LOGIN_SESSIONS = (
        'Service shall provide login sessions that conform with this '
        'specification.'
    )
    SEC_SESSIONS_URI_LOCATION = (
        'To establish a session, find the URI in either the Session '
        'Service\'s Sessions property or the Service Root\'s links property '
        'under the Sessions property. Both URIs shall be the same.'
    )
    SEC_SESSION_POST_RESPONSE = (
        'The response to the POST request to create a session shall include '
        '[X-Auth-Token header, Location header, and JSON body containing the '
        'full representation of the new session resource.]'
    )
    SEC_SESSION_CREATE_HTTPS_ONLY = (
        'The POST to create a session shall only be supported with HTTPS.'
    )
    SEC_SESSION_TERMINATION_SIDE_EFFECTS = (
        'When a session is terminated, the service shall not affect '
        'independent connections established originally by this session for '
        'other purposes, such as connections for Server-Sent Events or '
        'transferring an image for the Update Service.'
    )
    SEC_ACCOUNTS_SUPPORT_ETAGS = (
        'User accounts shall support ETags and atomic operations.'
    )
    SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN = (
        '[When using an account with PasswordChangeRequired set to true] the '
        'service shall allow a session login and include a '
        '@Message.ExtendedInfo object in the response containing the '
        'PasswordChangeRequired message from the Base Message Registry.'
    )
    SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT = (
        '[When using an account with PasswordChangeRequired set to true] the '
        'service shall allow a GET operation on the ManagerAccount resource '
        'associated with the account.'
    )
    SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD = (
        '[When using an account with PasswordChangeRequired set to true] the '
        'service shall allow a PATCH operation on the ManagerAccount '
        'resource associated with the account to update the Password '
        'property. If the value of Password is changed, the service shall '
        'also set the PasswordChangeRequired property to false.'
    )
    SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS = (
        'For all other operations [when using an account with '
        'PasswordChangeRequired set to true], the service shall respond with '
        'the HTTP 403 Forbidden status code and include a '
        '@Message.ExtendedInfo object that contains the '
        'PasswordChangeRequired message from the Base Message Registry.'
    )
    SEC_PRIV_ONE_ROLE_PRE_USER = (
        'Each user shall be assigned exactly one role.'
    )
    SEC_PRIV_SUPPORT_PREDEFINED_ROLES = (
        'Services shall support the previous predefined roles [Administrator, '
        'Operator, and ReadOnly].'
    )
    SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE = (
        'The AssignedPrivileges property in the Role resource for the '
        'predefined roles shall not be modifiable.'
    )
    SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE = (
        'A predefined role or a custom role shall be assigned to a user when '
        'a manager account is created.'
    )
    SEC_PRIV_OPERATION_TO_PRIV_MAPPING = (
        'For every request that a client makes to a service, the service '
        'shall determine that the authenticated identity of the requester has '
        'the authorization to complete the requested operation on the '
        'resource in the request.'
    )
