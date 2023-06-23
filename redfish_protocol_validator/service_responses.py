# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import io
import xml.etree.ElementTree as ET

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, RequestType, ResourceType, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest


def test_header_present(sut: SystemUnderTest, header, uri, method, response,
                        assertion):
    """Test that header is present in the response."""
    if response is None:
        msg = ('No response found for %s request to %s; unable to '
               'test this assertion' % (method, uri))
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, method, status, uri, assertion, msg)
    else:
        v = response.headers.get(header)
        if v:
            if header == 'X-Auth-Token':
                msg = 'Test passed for header %s' % header
            else:
                msg = 'Test passed for header %s: %s' % (header, v)
            sut.log(Result.PASS, response.request.method,
                    response.status_code, uri, assertion, msg)
        else:
            msg = ('The %s header was missing from the response to the '
                   '%s request to URI %s' %
                   (header, response.request.method, uri))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, uri,
                    assertion, msg)


def test_header_value(sut: SystemUnderTest, header, value, uri, method,
                      response, assertion):
    """Test that header is present in the response."""
    if response is None:
        msg = ('No response found for %s request to %s; unable to '
               'test this assertion' % (method, uri))
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, method, status, uri, assertion, msg)
    else:
        v = response.headers.get(header)
        if v is None:
            msg = ('The %s header was missing from the response to the '
                   '%s request to URI %s' %
                   (header, response.request.method, uri))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, uri,
                    assertion, msg)
        elif (header == 'Content-Type' and
              value == utils.get_response_media_type(response)):
            msg = 'Test passed for header %s: %s' % (header, v)
            sut.log(Result.PASS, response.request.method,
                    response.status_code, uri, assertion, msg)
        elif value == response.headers.get(header):
            msg = 'Test passed for header %s: %s' % (header, v)
            sut.log(Result.PASS, response.request.method,
                    response.status_code, uri, assertion, msg)
        else:
            msg = ('The %s header value from the response to the '
                   '%s request to URI %s was %s; expected %s' %
                   (header, response.request.method, uri, v, value))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, uri, assertion, msg)


def test_allow_header_method_not_allowed(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED."""
    found_method_not_allowed = False
    for req_type in [RequestType.NORMAL, RequestType.PATCH_COLLECTION,
                     RequestType.PATCH_RO_RESOURCE, RequestType.UNSUPPORTED_REQ]:
        for uri, response in sut.get_all_responses(request_type=req_type):
            if response.status_code == requests.codes.METHOD_NOT_ALLOWED:
                found_method_not_allowed = True
                val = response.headers.get('Allow')
                if val:
                    msg = 'Test passed for header %s: %s' % ('Allow', val)
                    sut.log(Result.PASS, response.request.method,
                            response.status_code, uri,
                            Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED,
                            msg)
                else:
                    msg = ('The Allow header was missing from response to %s '
                           'request to %s' % (response.request.method, uri))
                    sut.log(Result.FAIL, response.request.method,
                            response.status_code, uri,
                            Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED,
                            msg)

    if not found_method_not_allowed:
        msg = ('No responses found that returned a %s status code; unable to '
               'test this assertion' % requests.codes.METHOD_NOT_ALLOWED)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED, msg)


def test_allow_header_get_or_head(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD."""
    uri = '/redfish/v1/'
    for method in ['GET', 'HEAD']:
        response = sut.get_response(method, uri)
        if response is None:
            msg = 'No response found for %s request to %s' % (method, uri)
            sut.log(Result.NOT_TESTED, method, '', uri,
                    Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD, msg)
        elif response.status_code == requests.codes.NOT_IMPLEMENTED:
            msg = '%s not implemented on URI %s' % (method, uri)
            sut.log(Result.NOT_TESTED, method, response.status_code, uri,
                    Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD, msg)
        else:
            test_header_present(sut, 'Allow', uri, method, response,
                                Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD)


def test_cache_control_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_CACHE_CONTROL."""
    uri = '/redfish/v1/'
    method = 'GET'
    response = sut.get_response(method, uri)
    if response is None or not response.ok:
        msg = ('No successful response found for %s request to %s; unable to '
               'test this assertion' % (method, uri))
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, method, status, uri,
                Assertion.RESP_HEADERS_CACHE_CONTROL, msg)
    else:
        test_header_present(sut, 'Cache-Control', uri, method, response,
                            Assertion.RESP_HEADERS_CACHE_CONTROL)


def test_content_type_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_CONTENT_TYPE."""
    header = 'Content-Type'
    method = 'GET'
    uri_media_types = [
        ('/redfish/v1/', 'application/json', RequestType.NORMAL),
        ('/redfish/v1/$metadata', 'application/xml', RequestType.NORMAL),
        ('/redfish/v1/openapi.yaml', 'application/yaml', RequestType.YAML),
        (sut.server_sent_event_uri, 'text/event-stream', RequestType.STREAMING)
    ]
    for uri, media, req_type in uri_media_types:
        if uri:
            response = sut.get_response(method, uri, request_type=req_type)
            if response is None or not response.ok:
                msg = ('No successful response found for %s request to %s; '
                       'unable to test this assertion' % (method, uri))
                status = response.status_code if response is not None else ''
                sut.log(Result.NOT_TESTED, method, status, uri,
                        Assertion.RESP_HEADERS_CONTENT_TYPE, msg)
            else:
                test_header_value(sut, header, media, uri, method, response,
                                  Assertion.RESP_HEADERS_CONTENT_TYPE)


def test_etag_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ETAG."""
    method = 'GET'
    found_response = False
    for uri, response in sut.get_responses_by_method(
            method, resource_type=ResourceType.MANAGER_ACCOUNT).items():
        if response.ok:
            found_response = True
            test_header_present(sut, 'ETag', uri, method, response,
                                Assertion.RESP_HEADERS_ETAG)
    if not found_response:
        msg = ('No successful response found for %s request to '
               'ManagerAccount; unable to test this assertion' % method)
        sut.log(Result.NOT_TESTED, method, '', '',
                Assertion.RESP_HEADERS_ETAG, msg)


def test_link_header_schema_ver_match(sut: SystemUnderTest, uri_ref, uri,
                                      method, response):
    """Perform tests for Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH."""
    if not uri_ref:
        msg = ('The Link header with a rel=describedby param did not include '
               'a URI reference')
        sut.log(Result.FAIL, method, response.status_code, uri,
                Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH, msg)
        return

    # get the version from the uri_ref
    ver = None
    base = uri_ref.rstrip('/').rsplit('/')[-1]
    if base.endswith('.json'):
        base = base[:-5]
    base = base.split('.')
    if len(base) == 2 and base[1].startswith('v'):
        ver = base[1]

    # get the version from the @odata.type
    ot_ver = None
    data = response.json()
    odata_type = data.get('@odata.type')
    if odata_type:
        t = odata_type.lstrip('#').split('.')
        if len(t) == 3:
            ot_ver = t[1]

    if ver:
        if ver == ot_ver:
            msg = ('Test passed for versioned resource %s.%s' %
                   (base[0], base[1]))
            sut.log(Result.PASS, method, response.status_code, uri,
                    Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH, msg)
        else:
            msg = ('The resource version from the Link header (%s) did not '
                   'match the resource version from the @odata.type property '
                   '(%s)' % (uri_ref, odata_type))
            sut.log(Result.FAIL, method, response.status_code, uri,
                    Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH, msg)
    else:
        msg = ('Test passed for unversioned resource %s' % base[0])
        sut.log(Result.PASS, method, response.status_code, uri,
                Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH, msg)


def test_link_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY."""
    # a selection of URis to test
    uris = ['/redfish/v1/', sut.sessions_uri, sut.mgr_net_proto_uri,
            sut.systems_uri, sut.accounts_uri, sut.account_service_uri,
            sut.privilege_registry_uri]
    # eliminate URIs the service doesn't support
    uris = [u for u in uris if u is not None]
    for method in ['GET', 'HEAD']:
        for uri in uris:
            response = sut.get_response(method, uri)
            if response is None:
                continue
            elif not response.ok:
                msg = ('No successful response found for %s request to %s; '
                       'unable to test this assertion' % (method, uri))
                sut.log(Result.NOT_TESTED, method, response.status_code, uri,
                        Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY, msg)
            elif not response.links:
                msg = 'The response did not include a Link header'
                sut.log(Result.FAIL, method, response.status_code, uri,
                        Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY, msg)
            else:
                described_by = response.links.get('describedby')
                if described_by:
                    uri_ref = described_by.get('url')
                    msg = ('Test passed for header %s: %s' %
                           ('Link', response.headers.get('Link')))
                    sut.log(Result.PASS, response.request.method,
                            response.status_code, uri,
                            Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY, msg)
                    if (method == 'GET' and
                            response.status_code == requests.codes.OK):
                        test_link_header_schema_ver_match(sut, uri_ref, uri,
                                                          method, response)
                else:
                    msg = ('The response included a Link header, but not one '
                           'with a rel=describedby param; %s: %s' %
                           ('Link', response.headers.get('Link')))
                    sut.log(Result.FAIL, method, response.status_code, uri,
                            Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY, msg)


def test_location_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_LOCATION."""
    found_create_response = False
    for uri, response in sut.get_responses_by_method('POST').items():
        if response.status_code == requests.codes.CREATED:
            found_create_response = True
            test_header_present(sut, 'Location', uri, 'POST', response,
                                Assertion.RESP_HEADERS_LOCATION)
            if uri == sut.sessions_uri:
                test_header_present(sut, 'X-Auth-Token', uri, 'POST', response,
                                    Assertion.RESP_HEADERS_LOCATION)
    if not found_create_response:
        msg = ('No successful POST (create) response found; '
               'unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'POST', '', '',
                Assertion.RESP_HEADERS_LOCATION, msg)


def test_odata_version_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ODATA_VERSION."""
    uri = '/redfish/v1/'
    method = 'GET'
    header = 'OData-Version'
    response = sut.get_response(method, uri)
    test_header_value(sut, header, '4.0', uri, method, response,
                      Assertion.RESP_HEADERS_ODATA_VERSION)


def test_www_authenticate_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_WWW_AUTHENTICATE."""
    # a selection of URis to test
    uris = [sut.sessions_uri, sut.mgr_net_proto_uri, sut.systems_uri,
            sut.accounts_uri, sut.account_service_uri,
            sut.privilege_registry_uri]
    # eliminate URIs the service doesn't support
    uris = [u for u in uris if u is not None]
    found_unauthorized = False
    for uri in uris:
        for method in ['GET', 'POST', 'PATCH', 'DELETE']:
            response = sut.get_response(
                method, uri, request_type=RequestType.NO_AUTH)
            if (response is not None and
                    response.status_code == requests.codes.UNAUTHORIZED):
                found_unauthorized = True
                test_header_present(
                    sut, 'WWW-Authenticate', uri, response.request.method,
                    response, Assertion.RESP_HEADERS_WWW_AUTHENTICATE)
    if not found_unauthorized:
        msg = ('No 401 Unauthorized responses found; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.RESP_HEADERS_WWW_AUTHENTICATE, msg)


def test_x_auth_token_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_X_AUTH_TOKEN."""
    uri = sut.sessions_uri
    response = sut.get_response('POST', uri)
    if response is not None and response.status_code == requests.codes.CREATED:
        token = response.headers.get('X-Auth-Token')
        if token:
            is_random = utils.random_sequence(token)
            if is_random is None:
                msg = ('The security token is not a hexadecimal string; '
                       'unable to test this assertion')
                sut.log(Result.NOT_TESTED, 'POST', response.status_code,
                        uri, Assertion.RESP_HEADERS_X_AUTH_TOKEN, msg)
            elif is_random:
                msg = ('Test passed for header %s' % 'X-Auth-Token')
                sut.log(Result.PASS, 'POST', response.status_code,
                        uri, Assertion.RESP_HEADERS_X_AUTH_TOKEN, msg)
            else:
                msg = ('The security token from the %s header may not be '
                       'sufficiently random' % 'X-Auth-Token')
                sut.log(Result.WARN, 'POST', response.status_code,
                        uri, Assertion.RESP_HEADERS_X_AUTH_TOKEN, msg)
        else:
            msg = ('The %s header was missing from the response to the POST '
                   'request to the Sessions URI' % 'X-Auth-Token')
            sut.log(Result.FAIL, 'POST', response.status_code,
                    uri, Assertion.RESP_HEADERS_X_AUTH_TOKEN, msg)
    else:
        msg = ('No successful response found for POST to Sessions URI; '
               'unable to test this assertion')
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, 'POST', status,
                uri, Assertion.RESP_HEADERS_X_AUTH_TOKEN, msg)


def test_extended_error(sut: SystemUnderTest, status_code,
                        req_types, assertion):
    """Test that response is an extended error."""
    bad_request_found = False
    for req_type in req_types:
        for uri, response in sut.get_all_responses(request_type=req_type):
            if response.status_code == status_code:
                bad_request_found = True
                if (utils.get_response_media_type(response) !=
                        'application/json'):
                    msg = ('The response payload type was %s; expected %s' %
                           (response.headers.get('Content-Type', '<missing>'),
                            'application/json'))
                    sut.log(Result.FAIL, response.request.method,
                            response.status_code, uri, assertion, msg)
                    continue
                data = response.json()
                if 'error' in data:
                    if 'code' in data['error'] and 'message' in data['error']:
                        sut.log(Result.PASS, response.request.method,
                                response.status_code, uri, assertion,
                                'Test passed')
                    else:
                        msg = ('The required "code" or "message" properties '
                               'were missing from the error response')
                        sut.log(Result.FAIL, response.request.method,
                                response.status_code, uri, assertion, msg)
                else:
                    msg = ('The required "error" property was missing from '
                           'the error response')
                    sut.log(Result.FAIL, response.request.method,
                            response.status_code, uri, assertion, msg)
    if not bad_request_found:
        msg = ('No response with a %s status code was found; '
               'unable to test this assertion' % status_code)
        sut.log(Result.NOT_TESTED, '', '', '', assertion, msg)


def test_status_bad_request(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_STATUS_BAD_REQUEST."""
    req_types = [RequestType.PATCH_BAD_PROP, RequestType.PATCH_ODATA_PROPS]
    test_extended_error(sut, requests.codes.BAD_REQUEST, req_types,
                        Assertion.RESP_STATUS_BAD_REQUEST)


def test_status_internal_server_error(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_STATUS_INTERNAL_SERVER_ERROR."""
    req_types = [RequestType.NORMAL, RequestType.STREAMING]
    test_extended_error(sut, requests.codes.SERVER_ERROR, req_types,
                        Assertion.RESP_STATUS_INTERNAL_SERVER_ERROR)


def test_odata_metadata_mime_type(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_ODATA_METADATA_MIME_TYPE."""
    uri = '/redfish/v1/$metadata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response found for URI %s; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.RESP_ODATA_METADATA_MIME_TYPE, msg)
    elif not response.ok:
        msg = ('%s request to URI %s failed with status %s'
               % ('GET', uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.RESP_ODATA_METADATA_MIME_TYPE, msg)
    else:
        mime_type = utils.get_response_media_type(response)
        charset = utils.get_response_media_type_charset(response)
        if mime_type == 'application/xml' and (charset is None or
                                               charset == 'charset=utf-8'):
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_METADATA_MIME_TYPE, 'Test passed')
        else:
            msg = ('The MIME type for the OData metadata document is %s; '
                   'expected %s or %s' % (
                    response.headers.get('Content-Type'), 'application/xml',
                    'application/xml;charset=utf-8'))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_METADATA_MIME_TYPE, msg)


def test_odata_metadata_entity_container(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER."""
    uri = '/redfish/v1/$metadata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response found for URI %s; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER, msg)
    elif not response.ok:
        msg = ('%s request to URI %s failed with status %s'
               % ('GET', uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER, msg)
    else:
        try:
            tree = ET.iterparse(io.StringIO(response.text))
            # strip the namespace
            for _, el in tree:
                _, _, el.tag = el.tag.rpartition('}')
            root = tree.root
            ec = None
            ds = root.find('DataServices')
            if ds is not None:
                schema = ds.find('Schema')
                if schema is not None:
                    ec = schema.find('EntityContainer')
            if ec is not None:
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER,
                        'Test passed')
            else:
                msg = ('EntityContainer element not found in OData metadata '
                       'document')
                sut.log(Result.FAIL, 'GET', response.status_code, uri,
                        Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER, msg)
        except Exception as e:
            msg = ('%s received while trying to read EntityContainer '
                   'element from the OData metadata document; error: "%s"' %
                   (e.__class__.__name__, e))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_METADATA_ENTITY_CONTAINER, msg)


def test_odata_service_mime_type(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_ODATA_SERVICE_MIME_TYPE."""
    uri = '/redfish/v1/odata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response found for URI %s; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.RESP_ODATA_SERVICE_MIME_TYPE, msg)
    elif not response.ok:
        msg = ('%s request to URI %s failed with status %s'
               % ('GET', uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.RESP_ODATA_SERVICE_MIME_TYPE, msg)
    else:
        mime_type = utils.get_response_media_type(response)
        if mime_type == 'application/json':
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_SERVICE_MIME_TYPE, 'Test passed')
        else:
            msg = ('The MIME type for the OData service document is %s; '
                   'expected %s' % (response.headers.get('Content-Type'),
                                    'application/json'))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_SERVICE_MIME_TYPE, msg)


def test_odata_service_context(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_ODATA_SERVICE_CONTEXT."""
    uri = '/redfish/v1/odata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response found for URI %s; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.RESP_ODATA_SERVICE_CONTEXT, msg)
    elif not response.ok:
        msg = ('%s request to URI %s failed with status %s'
               % ('GET', uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.RESP_ODATA_SERVICE_CONTEXT, msg)
    else:
        data = response.json()
        context = data.get('@odata.context')
        if context == '/redfish/v1/$metadata':
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_SERVICE_CONTEXT, 'Test passed')
        else:
            msg = ('The @odata.context property for the OData service '
                   'document is %s; expected %s' %
                   (context, '/redfish/v1/$metadata'))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_SERVICE_CONTEXT, msg)


def test_odata_service_value_prop(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_ODATA_SERVICE_VALUE_PROP."""
    uri = '/redfish/v1/odata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response found for URI %s; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.RESP_ODATA_SERVICE_VALUE_PROP, msg)
    elif not response.ok:
        msg = ('%s request to URI %s failed with status %s'
               % ('GET', uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.RESP_ODATA_SERVICE_VALUE_PROP, msg)
    else:
        data = response.json()
        value = data.get('value')
        if value is not None:
            if isinstance(value, list):
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.RESP_ODATA_SERVICE_VALUE_PROP, 'Test passed')
            else:
                msg = ('The value property for the OData service '
                       'document is type %s; expected list' %
                       value.__class__.__name__)
                sut.log(Result.FAIL, 'GET', response.status_code, uri,
                        Assertion.RESP_ODATA_SERVICE_VALUE_PROP, msg)
        else:
            msg = ('The value property for the OData service '
                   'document is missing')
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.RESP_ODATA_SERVICE_VALUE_PROP, msg)


def test_response_headers(sut: SystemUnderTest):
    """Perform tests from the 'Response headers' sub-section of the spec."""
    test_allow_header_method_not_allowed(sut)
    test_allow_header_get_or_head(sut)
    test_cache_control_header(sut)
    test_content_type_header(sut)
    test_etag_header(sut)
    test_link_header(sut)
    test_location_header(sut)
    test_odata_version_header(sut)
    test_www_authenticate_header(sut)
    test_x_auth_token_header(sut)


def test_response_status_codes(sut: SystemUnderTest):
    """Perform tests from the 'Status codes' sub-section of the spec."""
    test_status_bad_request(sut)
    test_status_internal_server_error(sut)


def test_response_odata_metadata(sut: SystemUnderTest):
    """Perform tests from the 'OData metadata' sub-section of the spec."""
    test_odata_metadata_mime_type(sut)
    test_odata_metadata_entity_container(sut)
    test_odata_service_mime_type(sut)
    test_odata_service_context(sut)
    test_odata_service_value_prop(sut)


def test_service_responses(sut: SystemUnderTest):
    """Perform tests from the 'Service responses' section of the spec."""
    test_response_headers(sut)
    test_response_status_codes(sut)
    test_response_odata_metadata(sut)
