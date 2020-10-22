# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import requests

from assertions import utils
from assertions.constants import Assertion, RequestType, ResourceType, Result
from assertions.system_under_test import SystemUnderTest


def test_access_control_allow_origin_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ACCESS_CONTROL_ALLOW_ORIGIN."""
    # TODO(bdodd): How can we test this?
    pass


def test_header_present(sut: SystemUnderTest, header, uri, method, response,
                        assertion):
    """Test that header is present in the response."""
    if response is None or response.status_code != requests.codes.OK:
        msg = ('No successful response found for %s request to %s; unable to '
               'test this assertion' % (method, uri))
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, method, status, uri, assertion, msg)
    else:
        v = response.headers.get(header)
        if v:
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
    if response is None or response.status_code != requests.codes.OK:
        msg = ('No successful response found for %s request to %s; unable to '
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
        elif value == utils.get_response_media_type(response):
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
                     RequestType.PATCH_RO_RESOURCE]:
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
        test_header_present(sut, 'Allow', uri, method, response,
                            Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD)


def test_cache_control_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_CACHE_CONTROL."""
    uri = '/redfish/v1/'
    method = 'GET'
    response = sut.get_response(method, uri)
    test_header_present(sut, 'Cache-Control', uri, method, response,
                        Assertion.RESP_HEADERS_CACHE_CONTROL)


def test_content_type_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_CONTENT_TYPE."""
    header = 'Content-Type'

    # JSON
    uri, method, media = '/redfish/v1/', 'GET', 'application/json'
    response = sut.get_response(method, uri)
    test_header_value(sut, header, media, uri, method, response,
                      Assertion.RESP_HEADERS_CONTENT_TYPE)

    # XML
    uri, method, media = '/redfish/v1/$metadata', 'GET', 'application/xml'
    response = sut.get_response(method, uri)
    test_header_value(sut, header, media, uri, method, response,
                      Assertion.RESP_HEADERS_CONTENT_TYPE)

    # YAML
    uri, method, media = '/redfish/v1/openapi.yaml', 'GET', 'application/yaml'
    response = sut.get_response(method, uri, request_type=RequestType.YAML)
    test_header_value(sut, header, media, uri, method, response,
                      Assertion.RESP_HEADERS_CONTENT_TYPE)

    # SSE
    if sut.server_sent_event_uri:
        uri, method, media = (sut.server_sent_event_uri, 'GET',
                              'text/event-stream')
        response = sut.get_response(method, uri,
                                    request_type=RequestType.STREAMING)
        test_header_value(sut, header, media, uri, method, response,
                          Assertion.RESP_HEADERS_CONTENT_TYPE)


def test_etag_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ETAG."""
    method = 'GET'
    for uri, response in sut.get_responses_by_method(
            method, resource_type=ResourceType.MANAGER_ACCOUNT).items():
        test_header_present(sut, 'ETag', uri, method, response,
                            Assertion.RESP_HEADERS_ETAG)


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


def test_odata_version_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_ODATA_VERSION."""


def test_www_authenticate_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_WWW_AUTHENTICATE."""


def test_x_auth_token_header(sut: SystemUnderTest):
    """Perform tests for Assertion.RESP_HEADERS_X_AUTH_TOKEN."""


def test_response_headers(sut: SystemUnderTest):
    """Perform tests from the 'Response headers' sub-section of the spec."""
    test_access_control_allow_origin_header(sut)
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


def test_service_responses(sut: SystemUnderTest):
    """Perform tests from the 'Service responses' section of the spec."""
    test_response_headers(sut)
