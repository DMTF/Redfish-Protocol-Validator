# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
from urllib.parse import urlparse

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, RequestType, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest


def test_header(sut: SystemUnderTest, header, header_values, uri, assertion,
                stream=False):
    """Perform test for a particular header value"""
    for val in header_values:
        response = sut.session.get(sut.rhost + uri, headers={header: val},
                                   stream=stream)
        if response.ok:
            msg = 'Test passed for header %s: %s' % (header, val)
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    assertion, msg)
            if stream:
                response.close()
        elif response.status_code == requests.codes.NOT_FOUND:
            msg = ('Resource at URI %s not found; unable to test this '
                   'assertion for header %s' % (uri, header))
            sut.log(Result.NOT_TESTED, 'GET', response.status_code, uri,
                    assertion, msg)
            break
        else:
            msg = ('GET request to %s failed with status code %s using header '
                   '%s: %s; extended error: %s' %
                   (uri, response.status_code, header, val,
                    utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    assertion, msg)


def test_accept_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_ACCEPT."""
    header = 'Accept'
    assertion = Assertion.REQ_HEADERS_ACCEPT

    # JSON
    uri = '/redfish/v1/'
    header_values = ['application/json', 'application/json;charset=utf-8',
                     'application/*', 'application/*;charset=utf-8',
                     '*/*', '*/*;charset=utf-8']
    test_header(sut, header, header_values, uri, assertion)

    # XML
    uri = '/redfish/v1/$metadata'
    header_values = ['application/xml', 'application/xml;charset=utf-8',
                     'application/*', 'application/*;charset=utf-8',
                     '*/*', '*/*;charset=utf-8']
    test_header(sut, header, header_values, uri, assertion)

    # YAML
    uri = '/redfish/v1/openapi.yaml'
    header_values = ['application/yaml', 'application/yaml;charset=utf-8',
                     'application/*', 'application/*;charset=utf-8',
                     '*/*', '*/*;charset=utf-8']
    test_header(sut, header, header_values, uri, assertion)

    # SSE
    uri = sut.server_sent_event_uri
    header_values = ['text/event-stream', 'text/event-stream;charset=utf-8']
    if uri:
        try:
            test_header(sut, header, header_values, uri, assertion,
                        stream=True)
        except Exception as e:
            msg = ('Caught %s while opening SSE stream with valid '
                   '"text/event-stream" Accept headers' % e.__class__.__name__)
            sut.log(Result.FAIL, 'GET', '', uri, assertion, msg)


def test_authorization_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_AUTHORIZATION."""
    response = sut.get_response('GET', sut.sessions_uri,
                                request_type=RequestType.BASIC_AUTH)
    if response is None:
        msg = ('No response using a basic authentication header found; unable '
               'to test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_HEADERS_AUTHORIZATION, msg)
        return

    if 'Authorization' not in response.request.headers:
        msg = ('Expected basic authentication request to include an '
               'Authorization header, but it was not found in the request')
        sut.log(Result.WARN, 'GET', response.status_code,
                sut.sessions_uri, Assertion.REQ_HEADERS_AUTHORIZATION, msg)
        return

    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, sut.sessions_uri,
                Assertion.REQ_HEADERS_AUTHORIZATION,
                'Test passed for header Authorization')
    else:
        msg = ('Basic authentication request with Authorization header to '
               'protected URI failed')
        sut.log(Result.FAIL, 'GET', response.status_code,
                sut.sessions_uri, Assertion.REQ_HEADERS_AUTHORIZATION, msg)


def test_content_type_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_CONTENT_TYPE."""
    def test_content_type(val):
        for method in ['PATCH', 'POST']:
            for uri, response in sut.get_responses_by_method(method).items():
                if response.ok:
                    if val == response.request.headers.get('Content-Type'):
                        sut.log(Result.PASS, method, response.status_code, uri,
                                Assertion.REQ_HEADERS_CONTENT_TYPE,
                                'Test passed for header Content-Type: %s'
                                % val)
                        return
        msg = ('No successful PATCH or POST response found using header '
               'Content-Type: %s; unable to test this assertion for that '
               'Content-Type' % val)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_HEADERS_CONTENT_TYPE, msg)

    for content_type in ['application/json', 'application/json;charset=utf-8']:
        test_content_type(content_type)


def test_host_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_HOST."""
    uri = '/redfish/v1/'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('No response for GET request to URI %s found; unable '
               'to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.REQ_HEADERS_HOST, msg)
        return

    # Note: We cannot confirm that the Host header was sent by looking at
    # response.request.headers. That is because the requests package doesn't
    # add the Host header; the lower-level http.client package does. But rest
    # assured that it is added.

    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_HOST, 'Test passed for header Host')
    else:
        msg = ('GET request to URI %s was not successful; unable '
               'to test this assertion for header Host' % uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_HOST, msg)


def test_if_match_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_IF_MATCH."""
    def test_good_if_match():
        method = 'PATCH'
        for uri, response in sut.get_responses_by_method(method).items():
            if response.ok:
                if 'If-Match' in response.request.headers:
                    sut.log(Result.PASS, method, response.status_code, uri,
                            Assertion.REQ_HEADERS_IF_MATCH,
                            'Test passed for successful If-Match header')
                    return
        msg = ('No successful PATCH response using If-Match header '
               'was found; unable to test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_HEADERS_IF_MATCH, msg)

    def test_bad_if_match():
        method = 'PATCH'
        for uri, response in sut.get_responses_by_method(
                method, request_type=RequestType.BAD_ETAG).items():
            if response.status_code == requests.codes.PRECONDITION_FAILED:
                if 'If-Match' in response.request.headers:
                    sut.log(Result.PASS, method, response.status_code, uri,
                            Assertion.REQ_HEADERS_IF_MATCH,
                            'Test passed for unsuccessful If-Match header')
                    return
        msg = ('No PATCH response using incorrect If-Match header '
               'that returned status %s was found; unable to test this '
               'assertion' % requests.codes.PRECONDITION_FAILED)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_HEADERS_IF_MATCH, msg)

    test_good_if_match()
    test_bad_if_match()


def test_odata_version_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_ODATA_VERSION."""
    uri = '/redfish/v1/'

    # supported OData-Version
    response = sut.session.get(sut.rhost + uri,
                               headers={'OData-Version': '4.0'})
    if response.ok:
        msg = ('Test passed for supported header OData-Version: %s'
               % response.request.headers.get('OData-Version'))
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_ODATA_VERSION, msg)
    else:
        msg = ('Request failed with supported header OData-Version: %s'
               % response.request.headers.get('OData-Version'))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_ODATA_VERSION, msg)

    # unsupported OData-Version
    response = sut.session.get(sut.rhost + uri,
                               headers={'OData-Version': '4.1'})
    if response.status_code == requests.codes.PRECONDITION_FAILED:
        msg = ('Test passed for unsupported header OData-Version: %s'
               % response.request.headers.get('OData-Version'))
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_ODATA_VERSION, msg)
    else:
        msg = ('Request with unsupported header OData-Version: %s returned '
               'status %s; expected status %s' % (
                response.request.headers.get('OData-Version'),
                response.status_code, requests.codes.PRECONDITION_FAILED))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_ODATA_VERSION, msg)


def test_origin_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_ORIGIN."""
    # TODO(bdodd): How can we test this?
    pass


def test_user_agent_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_USER_AGENT."""
    uri = '/redfish/v1/'
    response = sut.get_response('GET', uri)
    if response is None or not response.ok:
        msg = ('No successful response for GET request to URI %s found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                uri, Assertion.REQ_HEADERS_USER_AGENT, msg)
    elif 'User-Agent' in response.request.headers:
        msg = ('Test passed for header User-Agent: %s' %
               response.request.headers.get('User-Agent'))
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_HEADERS_USER_AGENT,  msg)
    else:
        msg = ('No User-Agent header found in request; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                uri, Assertion.REQ_HEADERS_USER_AGENT, msg)


def test_x_auth_token_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEADERS_X_AUTH_TOKEN."""
    response = sut.get_response('GET', sut.sessions_uri)
    if response is None or not response.ok:
        msg = ('No successful response for GET request to URI %s found; '
               'unable to test this assertion' % sut.sessions_uri)
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                sut.sessions_uri, Assertion.REQ_HEADERS_X_AUTH_TOKEN, msg)
    elif 'X-Auth-Token' in response.request.headers:
        msg = 'Test passed for header X-Auth-Token'
        sut.log(Result.PASS, 'GET', response.status_code, sut.sessions_uri,
                Assertion.REQ_HEADERS_X_AUTH_TOKEN, msg)
    else:
        msg = ('No X-Auth-Token header found in request; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                sut.sessions_uri, Assertion.REQ_HEADERS_X_AUTH_TOKEN, msg)


def test_get_no_accept_header(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_NO_ACCEPT_HEADER."""
    uri = '/redfish/v1/'
    headers = {'Accept': None}
    response = sut.session.get(sut.rhost + uri, headers=headers)
    if response.ok:
        if utils.get_response_media_type(response) == 'application/json':
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_NO_ACCEPT_HEADER, 'Test passed')
        else:
            msg = ('Response from GET request to URI %s with no Accept header '
                   'contained a Content-Type of %s; expected %s' %
                   (uri, response.headers.get('Content-Type'),
                    'application/json'))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_NO_ACCEPT_HEADER, msg)
    else:
        msg = ('GET request to URI %s with no Accept header failed; extended '
               'error: %s' % (uri, utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_NO_ACCEPT_HEADER, msg)


def test_get_ignore_body(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_IGNORE_BODY."""
    uri = '/redfish/v1/'
    payload = {}
    response = sut.session.get(sut.rhost + uri, json=payload)
    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_GET_IGNORE_BODY, 'Test passed')
    else:
        msg = ('GET request to URI %s that included a body failed' % uri)
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_IGNORE_BODY, msg)


def test_get_collection_count_prop_required(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED."""
    uri = sut.sessions_uri
    response = sut.get_response('GET', uri)
    if response is None or not response.ok:
        msg = ('Successful response for GET request to URI %s not found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                uri, Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED, msg)
        return

    data = response.json()
    if 'Members@odata.count' in data:
        count = data.get('Members@odata.count')
        if not isinstance(count, int):
            msg = ('The count property was present but the type was %s; '
                   'expected int' % count.__class__.__name__)
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED, msg)
        else:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED,
                    'Test passed')
    else:
        msg = ('The collection resource at URI %s did not include the '
               'required count property (Members@odata.count)' % uri)
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED, msg)


def test_get_collection_count_prop_total(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL."""
    # TODO(bdodd): Try to find a collection resource with more members
    uri = sut.sessions_uri
    response = sut.get_response('GET', uri)
    if response is None or not response.ok:
        msg = ('Successful response for GET request to URI %s not found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET',
                response.status_code if response is not None else '',
                uri, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL, msg)
        return

    data = response.json()
    if 'Members@odata.count' not in data:
        msg = ('The collection resource at URI %s did not include the '
               'required count property' % uri)
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL, msg)
        return

    if 'Members' not in data:
        msg = ('The collection resource at URI %s did not include the '
               'Members property' % uri)
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL, msg)
        return

    count = data.get('Members@odata.count')
    members = len(data.get('Members'))
    if data.get('Members@odata.nextLink'):
        # TODO(bdodd): Loop through all next links and count the actual members
        if count > members:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
                    'Test passed')
        else:
            msg = ('Collection resource %s contained a next link property but '
                   'the count property (%s) was less than or equal to the '
                   'number of members in the original resource (%s)'
                   % (uri, count, members))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
                    msg)
    else:
        if count == members:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
                    'Test passed')
        else:
            msg = ('Collection resource %s did not contain a next link '
                   'property but the count property (%s) was not equal to the '
                   'number of members in the resource (%s)'
                   % (uri, count, members))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
                    msg)


def test_get_service_root_url(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_SERVICE_ROOT_URL."""
    uri = '/redfish/v1/'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('Response for GET request to Service Root URL %s not found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.REQ_GET_SERVICE_ROOT_URL, msg)
        return

    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_GET_SERVICE_ROOT_URL, 'Test passed')
    else:
        msg = ('GET request to Service Root URL %s failed with status code %s'
               % (uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_SERVICE_ROOT_URL, msg)


def test_get_service_root_no_auth(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH."""
    for uri in ['/redfish', '/redfish/v1/']:
        response = sut.get_response(
            'GET', uri, request_type=RequestType.NO_AUTH)
        if response is None:
            msg = ('Response for GET request with no authentication to '
                   'URL %s not found; unable to test this assertion' % uri)
            sut.log(Result.NOT_TESTED, 'GET', '', uri,
                    Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH, msg)
        elif response.ok:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH, 'Test passed')
        else:
            msg = ('GET request with no authentication to URL %s '
                   'failed with status code %s' % (uri, response.status_code))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH, msg)


def test_get_metadata_uri(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_METADATA_URI."""
    uri = '/redfish/v1/$metadata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('Response for GET request to metadata URI %s not found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.REQ_GET_METADATA_URI, msg)
        return

    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_GET_METADATA_URI, 'Test passed')
    else:
        msg = ('GET request to metadata URI %s failed with status code %s'
               % (uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_METADATA_URI, msg)


def test_get_odata_uri(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_ODATA_URI."""
    uri = '/redfish/v1/odata'
    response = sut.get_response('GET', uri)
    if response is None:
        msg = ('Response for GET request to OData URI %s not found; '
               'unable to test this assertion' % uri)
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.REQ_GET_ODATA_URI, msg)
        return

    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_GET_ODATA_URI, 'Test passed')
    else:
        msg = ('GET request to OData URI %s failed with status code %s'
               % (uri, response.status_code))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_GET_ODATA_URI, msg)


def test_get_metadata_odata_no_auth(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_GET_METADATA_ODATA_NO_AUTH."""
    for uri in ['/redfish/v1/$metadata', '/redfish/v1/odata']:
        response = sut.get_response(
            'GET', uri, request_type=RequestType.NO_AUTH)
        if response is None:
            msg = ('Response for GET request with no authentication to '
                   'URI %s not found; unable to test this assertion' % uri)
            sut.log(Result.NOT_TESTED, 'GET', '', uri,
                    Assertion.REQ_GET_METADATA_ODATA_NO_AUTH, msg)
        elif response.ok:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_METADATA_ODATA_NO_AUTH, 'Test passed')
        else:
            msg = ('GET request with no authentication to URI %s '
                   'failed with status code %s' % (uri, response.status_code))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_GET_METADATA_ODATA_NO_AUTH, msg)


def test_query_ignore_unsupported(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_QUERY_IGNORE_UNSUPPORTED."""
    uri = '/redfish/v1/?rpvunknown'
    response = sut.session.get(sut.rhost + uri)
    if response.ok:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_QUERY_IGNORE_UNSUPPORTED, 'Test passed')
    else:
        msg = ('GET request with unknown query parameter (URI %s) failed with '
               'status %s; expected query param to be ignored and the request '
               'to succeed; extended error: %s' %
               (uri, response.status_code, utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_QUERY_IGNORE_UNSUPPORTED, msg)


def test_query_unsupported_dollar_params_ext_error(
        sut: SystemUnderTest, uri, response):
    """Perform tests for Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR."""

    # Removing test for now; there are no standard messages that allow a service to specify the query parameter not supported

    """
    if ('application/json' in response.headers.get('Content-Type', '') and
            '@Message.ExtendedInfo' in response.text):
        data = response.json()
        if utils.is_text_in_extended_error('rpvunknown', data):
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
                    'Test passed')
        else:
            msg = ('The response contained an extended error, but the '
                   'unsupported query parameter $rpvunknown was not '
                   'indicated in the error message text; extended error: %s'
                   % utils.get_extended_error(response))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
                    msg)
    else:
        msg = 'The response did not contain an extended error'
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
                msg)
    """

def test_query_unsupported_dollar_params(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS."""
    uri = '/redfish/v1/?$rpvunknown'
    response = sut.session.get(sut.rhost + uri)
    if response.status_code == requests.codes.NOT_IMPLEMENTED:
        sut.log(Result.PASS, 'GET', response.status_code, uri,
                Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS, 'Test passed')
        test_query_unsupported_dollar_params_ext_error(sut, uri, response)
    else:
        msg = ('GET request with unknown query parameter that starts with $ '
               '(URI %s) returned status %s; expected status %s; extended '
               'error: %s' % (uri, response.status_code,
                              requests.codes.NOT_IMPLEMENTED,
                              utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'GET', response.status_code, uri,
                Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS, msg)
        if not response.ok:
            test_query_unsupported_dollar_params_ext_error(sut, uri, response)


def test_query_invalid_values(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_QUERY_INVALID_VALUES."""
    uris = []
    if sut.supported_query_params.get('OnlyMemberQuery'):
        uris.append(sut.sessions_uri + '?only=foo')
    if sut.supported_query_params.get('ExcerptQuery'):
        uris.append('/redfish/v1/' + '?excerpt=foo')

    if not uris:
        msg = ('The service does not support either the \'only\' or '
               '\'excerpt\' query parameters; unable to test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_QUERY_INVALID_VALUES, msg)
        return

    for uri in uris:
        response = sut.session.get(sut.rhost + uri)
        if response.status_code == requests.codes.BAD_REQUEST:
            sut.log(Result.PASS, 'GET', response.status_code, uri,
                    Assertion.REQ_QUERY_INVALID_VALUES,
                    'Test passed')
        else:
            msg = ('GET request with invalid query parameter (URI %s) '
                   'returned status %s; expected status %s' %
                   (uri, response.status_code, requests.codes.BAD_REQUEST))
            sut.log(Result.FAIL, 'GET', response.status_code, uri,
                    Assertion.REQ_QUERY_INVALID_VALUES, msg)


def test_head_differ_from_get(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_HEAD_DIFFERS_FROM_GET."""
    uri = '/redfish/v1/'
    response = sut.get_response('HEAD', uri)
    if response is None:
        msg = ('No HEAD request to uri %s found; unable to test this assertion'
               % uri)
        sut.log(Result.NOT_TESTED, 'HEAD', '', uri,
                Assertion.REQ_HEAD_DIFFERS_FROM_GET, msg)
    elif response.ok:
        if not response.text:
            sut.log(Result.PASS, 'HEAD', response.status_code, uri,
                    Assertion.REQ_HEAD_DIFFERS_FROM_GET, 'Test passed')
        else:
            msg = ('HEAD request to uri %s returned a non-empty body '
                   '(Content-Type: %s; Content-Length: %s)'
                   % (uri, response.headers.get('Content-Type', '<missing>'),
                       response.headers.get('Content-Length', '<missing>')))
            sut.log(Result.FAIL, 'HEAD', response.status_code, uri,
                    Assertion.REQ_HEAD_DIFFERS_FROM_GET, msg)
    elif (response.status_code == requests.codes.METHOD_NOT_ALLOWED or
            response.status_code == requests.codes.NOT_IMPLEMENTED):
        msg = 'HEAD not supported on URI %s' % uri
        sut.log(Result.NOT_TESTED, 'HEAD', response.status_code, uri,
                Assertion.REQ_HEAD_DIFFERS_FROM_GET, msg)
    else:
        msg = ('HEAD request to uri %s failed with status %s'
               % (uri, response.status_code))
        sut.log(Result.FAIL, 'HEAD', response.status_code, uri,
                Assertion.REQ_HEAD_DIFFERS_FROM_GET, msg)


def test_data_mod_errors(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_DATA_MOD_ERRORS."""
    found_error = False
    for uri, response in sut.get_responses_by_method('POST').items():
        if (not response.ok and
                response.status_code != requests.codes.METHOD_NOT_ALLOWED):
            found_error = True
            if response.headers.get('Location'):
                msg = ('POST request to uri %s failed with status %s, but '
                       'appeared to create resource %s'
                       % (uri, response.status_code,
                          response.headers.get('Location')))
                sut.log(Result.FAIL, 'POST', response.status_code, uri,
                        Assertion.REQ_DATA_MOD_ERRORS, msg)
            else:
                sut.log(Result.PASS, 'POST', response.status_code, uri,
                        Assertion.REQ_DATA_MOD_ERRORS, 'Test passed')

    if not found_error:
        msg = ('No failed POST responses found; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_DATA_MOD_ERRORS, msg)


def test_patch_mixed_props(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_MIXED_PROPS."""
    found_response = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', request_type=RequestType.PATCH_MIXED_PROPS).items():
        found_response = True
        if response.status_code == requests.codes.OK:
            data = response.json()
            if '@odata.id' in data:
                if '@Message.ExtendedInfo' in data:
                    sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_MIXED_PROPS, 'Test passed')
                else:
                    msg = ('The service response did not include a message '
                           'annotation that lists the non-updatable '
                           'properties')
                    sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_MIXED_PROPS, msg)
            else:
                msg = ('The service response did not include the resource '
                       'representation')
                sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_MIXED_PROPS, msg)
        elif response.status_code == requests.codes.BAD_REQUEST:
            sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_MIXED_PROPS, 'Test passed')
        else:
            msg = ('The service response returned status code %s; expected '
                   '%s; extended error: %s'
                   % (response.status_code, requests.codes.OK,
                      utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_MIXED_PROPS, msg)

    if not found_response:
        msg = ('No PATCH responses found for this condition; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_PATCH_MIXED_PROPS, msg)


def test_patch_bad_prop(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_BAD_PROP."""
    found_response = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', request_type=RequestType.PATCH_BAD_PROP).items():
        found_response = True
        if response.status_code == requests.codes.BAD_REQUEST:
            data = response.json()
            if ('error' in data and
                    utils.is_text_in_extended_error('BogusProp', data)):
                sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_BAD_PROP, 'Test passed')
            else:
                msg = ('The service response did not include a message '
                       'that lists the non-updatable property; extended '
                       'error: %s' % utils.get_extended_error(response))
                sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_BAD_PROP, msg)
        else:
            msg = ('The service response returned status code %s; expected '
                   '%s; extended error: %s'
                   % (response.status_code, requests.codes.BAD_REQUEST,
                      utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_BAD_PROP, msg)

    if not found_response:
        msg = ('No PATCH responses found for this condition; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_PATCH_BAD_PROP, msg)


def test_patch_ro_resource(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_RO_RESOURCE."""
    found_response = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', request_type=RequestType.PATCH_RO_RESOURCE).items():
        found_response = True
        if response.status_code == requests.codes.METHOD_NOT_ALLOWED:
            sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_RO_RESOURCE, 'Test passed')
        else:
            msg = ('The service response returned status code %s; expected %s'
                   % (response.status_code, requests.codes.METHOD_NOT_ALLOWED))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_RO_RESOURCE, msg)

    if not found_response:
        msg = ('No PATCH responses found for this condition; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_PATCH_RO_RESOURCE, msg)


def test_patch_collection(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_COLLECTION."""
    found_response = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', request_type=RequestType.PATCH_COLLECTION).items():
        found_response = True
        if response.status_code == requests.codes.METHOD_NOT_ALLOWED:
            sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_COLLECTION, 'Test passed')
        else:
            msg = ('The service response returned status code %s; expected %s'
                   % (response.status_code, requests.codes.METHOD_NOT_ALLOWED))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_COLLECTION, msg)

    if not found_response:
        msg = ('No PATCH responses found for this condition; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_PATCH_COLLECTION, msg)


def test_patch_odata_props(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_ODATA_PROPS."""
    found_response = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', request_type=RequestType.PATCH_ODATA_PROPS).items():
        found_response = True
        if response.status_code == requests.codes.BAD_REQUEST:
            data = response.json()
            if ('error' in data and 'NoOperation' in
                    utils.get_extended_info_message_keys(data)):
                sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_ODATA_PROPS, 'Test passed')
            else:
                msg = ('The service response did not include the NoOperation '
                       'message from the Base Message Registry; extended '
                       'error: %s' % utils.get_extended_error(response))
                sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_ODATA_PROPS, msg)
        elif response.status_code in [requests.codes.OK,
                                      requests.codes.ACCEPTED,
                                      requests.codes.NO_CONTENT]:
            sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_ODATA_PROPS, 'Test passed')
        else:
            exp_codes = [requests.codes.OK, requests.codes.ACCEPTED,
                         requests.codes.NO_CONTENT, requests.codes.BAD_REQUEST]
            msg = ('The service response returned status code %s; expected '
                   'one of %s; extended error: %s'
                   % (response.status_code, exp_codes,
                      utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_ODATA_PROPS, msg)

    if not found_response:
        msg = ('No PATCH responses found for this condition; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_PATCH_ODATA_PROPS, msg)


def patch_array_save(sut: SystemUnderTest):
    """Save the original array, if found."""
    array = None
    if sut.mgr_net_proto_uri:
        response = sut.get_response('GET', sut.mgr_net_proto_uri)
        if response is not None and response.ok:
            a = response.json().get('NTP', {}).get('NTPServers', None)
            if isinstance(a, list):
                array = a
    return array


def test_patch_array_element_remove(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE."""
    payload1 = {
        'NTP': {
            'NTPServers': [
                'time-a-b.nist.gov',
                'time-b-b.nist.gov'
            ]
        }
    }
    payload2 = {
        'NTP': {
            'NTPServers': [
                None,
                'time-b-b.nist.gov'
            ]
        }
    }
    uri = sut.mgr_net_proto_uri
    headers = utils.get_etag_header(sut, sut.session, uri)
    response = sut.session.patch(sut.rhost + uri,
                                 json=payload1, headers=headers)
    if response.ok:
        headers = utils.get_etag_header(sut, sut.session, uri)
        response = sut.session.patch(
            sut.rhost + uri, json=payload2, headers=headers)
        if response.ok:
            get_resp = sut.session.get(sut.rhost + uri)
            if get_resp.ok:
                array = get_resp.json().get('NTP', {}).get('NTPServers', None)
            else:
                array = response.json().get('NTP', {}).get('NTPServers', None)
            if isinstance(array, list):
                if 'time-a-b.nist.gov' in array:
                    msg = ('Array element %s was not removed; resource: %s; '
                           'PATCH payload: %s; resulting array: %s' %
                           ('time-a-b.nist.gov', payload1,
                            payload2, array))
                    sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE, msg)
                else:
                    sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'Test passed')
            else:
                msg = ('After PATCH, NTPServers array not found in response; '
                       'resource: %s; PATCH payload: %s' %
                       (payload1, payload2))
                sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE, msg)
        else:
            msg = ('PATCH failed with status %s; resource: %s; '
                   'PATCH payload: %s; extended error: %s' % (
                       response.status_code, payload1,
                       payload2, utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE, msg)
    else:
        msg = ('PATCH failed with status %s; PATCH payload: %s; extended '
               'error: %s' % (response.status_code, payload1,
                              utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE, msg)


def test_patch_array_element_unchanged(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED."""
    payload1 = {
        'NTP': {
            'NTPServers': [
                'time-a-b.nist.gov',
                'time-b-b.nist.gov'
            ]
        }
    }
    payload2 = {
        'NTP': {
            'NTPServers': [
                {},
                'time-d-b.nist.gov'
            ]
        }
    }
    uri = sut.mgr_net_proto_uri
    headers = utils.get_etag_header(sut, sut.session, uri)
    response = sut.session.patch(sut.rhost + uri,
                                 json=payload1, headers=headers)
    if response.ok:
        headers = utils.get_etag_header(sut, sut.session, uri)
        response = sut.session.patch(
            sut.rhost + uri, json=payload2, headers=headers)
        if response.ok:
            get_resp = sut.session.get(sut.rhost + uri)
            if get_resp.ok:
                array = get_resp.json().get('NTP', {}).get('NTPServers', None)
            else:
                array = response.json().get('NTP', {}).get('NTPServers', None)
            if isinstance(array, list):
                if 'time-a-b.nist.gov' in array:
                    sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
                            'Test passed')
                else:
                    missing = []
                    if 'time-a-b.nist.gov' not in array:
                        missing.append('time-a-b.nist.gov')
                    msg = ('After PATCH, the following NTPServers array '
                           'elements should have been left unchanged, but '
                           'were not found in the response: %s; resource: %s; '
                           'PATCH payload: %s' % (missing, payload1, payload2))
                    sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                            Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED, msg)
            else:
                msg = ('After PATCH, NTPServers array not found in response; '
                       'resource: %s; PATCH payload: %s' %
                       (payload1, payload2))
                sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED, msg)
            return response, array
        else:
            msg = ('PATCH failed with status %s; resource: %s; '
                   'PATCH payload: %s' % (
                       response.status_code, payload1,
                       payload2))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED, msg)
    else:
        msg = ('PATCH failed with status %s; PATCH payload: %s' %
               (response.status_code, payload1))
        sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED, msg)


def test_patch_array_operations_order(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_ARRAY_OPERATIONS_ORDER."""
    # TODO(bdodd): Need more thought on how to test this


def test_patch_array_truncate(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PATCH_ARRAY_TRUNCATE."""
    payload1 = {
        'NTP': {
            'NTPServers': [
                'time-a-b.nist.gov',
                'time-b-b.nist.gov'
            ]
        }
    }
    payload2 = {
        'NTP': {
            'NTPServers': [
                'time-b-b.nist.gov'
            ]
        }
    }
    expected_array = ['time-b-b.nist.gov']
    uri = sut.mgr_net_proto_uri
    headers = utils.get_etag_header(sut, sut.session, uri)
    response = sut.session.patch(sut.rhost + uri, json=payload1,
                                 headers=headers)
    if response.ok:
        headers = utils.get_etag_header(sut, sut.session, uri)
        response = sut.session.patch(
            sut.rhost + uri, json=payload2, headers=headers)
        if response.ok:
            get_resp = sut.session.get(sut.rhost + uri)
            if get_resp.ok:
                array = get_resp.json().get('NTP', {}).get('NTPServers', None)
            else:
                array = response.json().get('NTP', {}).get('NTPServers', None)
            if isinstance(array, list):
                # Remove trailing "null" instance; services might implement
                # this as a fixed array and show the array size by padding with
                # null entries
                while array and array[-1] is None:
                    array.pop()
                if array == expected_array:
                    sut.log(Result.PASS, 'PATCH', response.status_code,
                            uri, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
                            'Test passed')
                else:
                    msg = ('After PATCH, expected NTPServers array to be %s; '
                           'found: %s; resource: %s; PATCH payload: %s' % (
                               expected_array, array, payload1,
                               payload2))
                    sut.log(Result.FAIL, 'PATCH', response.status_code,
                            uri, Assertion.REQ_PATCH_ARRAY_TRUNCATE, msg)
            else:
                msg = ('After PATCH, NTPServers array not found in response; '
                       'resource: %s; PATCH payload: %s' %
                       (payload1, payload2))
                sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, uri,
                        Assertion.REQ_PATCH_ARRAY_TRUNCATE, msg)
        else:
            msg = ('PATCH failed with status %s; resource: %s; '
                   'PATCH payload: %s; extended error: %s' %
                   (response.status_code, payload1,
                    payload2, utils.get_extended_error(response)))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.REQ_PATCH_ARRAY_TRUNCATE, msg)
    else:
        msg = ('PATCH failed with status %s; PATCH payload: %s; extended '
               'error: %s' % (response.status_code, payload1,
                              utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                Assertion.REQ_PATCH_ARRAY_TRUNCATE, msg)


def patch_array_restore(sut: SystemUnderTest, array):
    """Restore the original array."""
    uri = sut.mgr_net_proto_uri
    payload = {
        'NTP': {
            'NTPServers': array
        }
    }
    headers = utils.get_etag_header(sut, sut.session, uri)
    response = sut.session.patch(sut.rhost + uri,
                                 json=payload, headers=headers)
    if not response.ok:
        logging.warning('Attempt to PATCH %s to restore the original '
                        'NTPServers array failed with status %s; PATCH '
                        'payload: %s' % (uri, response.status_code, payload))


def test_put_not_implemented(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_PUT_NOT_IMPLEMENTED."""
    # TODO(bdodd): Need a good resource to try to replace


def test_post_create_via_collection(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_POST_CREATE_VIA_COLLECTION."""
    response = sut.get_response('POST', sut.sessions_uri)
    if response is None:
        msg = ('Not response found for POST to Sessions URI; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, 'POST', '', sut.sessions_uri,
                Assertion.REQ_POST_CREATE_VIA_COLLECTION, msg)
    elif response.ok:
        sut.log(Result.PASS, 'POST', response.status_code, sut.sessions_uri,
                Assertion.REQ_POST_CREATE_VIA_COLLECTION, 'Test passed')
    else:
        msg = ('POST request to collections uri %s failed with status %s'
               % (sut.sessions_uri, response.status_code))
        sut.log(Result.FAIL, 'POST', response.status_code, sut.sessions_uri,
                Assertion.REQ_POST_CREATE_VIA_COLLECTION, msg)


def test_post_create_uri_in_location_hdr(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR."""
    response = sut.get_response('POST', sut.sessions_uri)
    if response is None or not response.ok:
        msg = ('No successful response found for POST to Sessions URI; '
               'unable to test this assertion')
        status = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, 'POST', status, sut.sessions_uri,
                Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR, msg)
    else:
        location = response.headers.get('Location')
        if location:
            sut.log(Result.PASS, 'POST', response.status_code,
                    sut.sessions_uri,
                    Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR,
                    'Test passed')
        else:
            msg = ('Location header missing from response to POST request to '
                   'uri %s failed with status %s'
                   % (sut.sessions_uri, response.status_code))
            sut.log(Result.FAIL, 'POST', response.status_code,
                    sut.sessions_uri,
                    Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR, msg)


def test_post_create_to_members_prop(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_POST_CREATE_TO_MEMBERS_PROP."""
    uri = sut.sessions_uri
    uri = uri + 'Members' if uri.endswith('/') else uri + '/Members'
    payload = {
        'UserName': sut.username,
        'Password': sut.password
    }
    headers = {
        'OData-Version': '4.0',
        'Content-Type': 'application/json;charset=utf-8'
    }
    response = requests.post(sut.rhost + uri, json=payload, headers=headers,
                             verify=sut.verify)
    if response.ok:
        sut.log(Result.PASS, 'POST', response.status_code, uri,
                Assertion.REQ_POST_CREATE_TO_MEMBERS_PROP,
                'Test passed')
        # clean-up the created session
        location = response.headers.get('Location')
        if location and isinstance(location, str):
            session_uri = urlparse(location).path
            if session_uri:
                sut.session.delete(sut.rhost + session_uri)
    else:
        msg = ('POST to Members property URI %s failed with status %s; '
               'extended error: %s' %
               (uri, response.status_code, utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'POST', response.status_code, uri,
                Assertion.REQ_POST_CREATE_TO_MEMBERS_PROP,
                msg)


def test_post_create_not_supported(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_POST_CREATE_NOT_SUPPORTED."""
    response = sut.get_response('POST', sut.accounts_uri)
    if response is None:
        msg = ('No response found for POST to Accounts URI; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, 'POST', '', sut.accounts_uri,
                Assertion.REQ_POST_CREATE_NOT_SUPPORTED, msg)
    elif response.ok:
        sut.log(Result.PASS, 'POST', response.status_code, sut.accounts_uri,
                Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                'Service supports creation of resources')
    elif response.status_code == requests.codes.METHOD_NOT_ALLOWED:
        sut.log(Result.PASS, 'POST', response.status_code, sut.accounts_uri,
                Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                'Test passed')
    else:
        try:
            allow = sut.get_response('GET', sut.accounts_uri).headers.get('Allow')
        except:
            allow = None
        if allow:
            if 'POST' in allow.upper():
                msg = ('POST request to URI %s failed with %s; extended '
                       'error: %s; GET response contains an Allow header '
                       'with POST specified' %
                       (sut.accounts_uri, response.status_code,
                        utils.get_extended_error(response)))
                sut.log(Result.WARN, 'POST', response.status_code,
                        sut.accounts_uri,
                        Assertion.REQ_POST_CREATE_NOT_SUPPORTED, msg)
            else:
                msg = ('POST request to URI %s failed with %s; expected %s; '
                       'extended error: %s' %
                       (sut.accounts_uri, response.status_code,
                        requests.codes.METHOD_NOT_ALLOWED,
                        utils.get_extended_error(response)))
                sut.log(Result.FAIL, 'POST', response.status_code,
                        sut.accounts_uri,
                        Assertion.REQ_POST_CREATE_NOT_SUPPORTED, msg)
        else:
            msg = ('POST request to URI %s failed with %s; expected %s; '
                   'extended error: %s; GET response does not contain an '
                   'Allow header to verify' %
                   (sut.accounts_uri, response.status_code,
                    requests.codes.METHOD_NOT_ALLOWED,
                    utils.get_extended_error(response)))
            sut.log(Result.WARN, 'POST', response.status_code,
                    sut.accounts_uri, Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                    msg)

def test_post_create_not_idempotent(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT."""
    uri = sut.sessions_uri
    payload = {
        'UserName': sut.username,
        'Password': sut.password
    }
    headers = {
        'OData-Version': '4.0',
        'Content-Type': 'application/json;charset=utf-8'
    }
    r1 = requests.post(sut.rhost + uri, json=payload, headers=headers,
                       verify=sut.verify)
    if r1.ok:
        loc1 = r1.headers.get('Location')
        session_uri1 = ''
        if loc1 and isinstance(loc1, str):
            session_uri1 = urlparse(loc1).path
        r2 = requests.post(sut.rhost + uri, json=payload, headers=headers,
                           verify=sut.verify)
        if r2.ok:
            loc2 = r2.headers.get('Location')
            session_uri2 = ''
            if loc2 and isinstance(loc2, str):
                session_uri2 = urlparse(loc2).path
                if loc1 == loc2:
                    # FAIL
                    msg = ('Two consecutive POST requests to %s succeeded, '
                           'but each returned the same resource URI in the '
                           'Location header (%s)' % (uri, loc1))
                    sut.log(Result.FAIL, 'POST', r2.status_code, uri,
                            Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT, msg)
                else:
                    sut.log(Result.PASS, 'POST', r1.status_code, uri,
                            Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
                            'Test passed')
            else:
                msg = ('POST request to %s did not return a Location header; '
                       'unable to test this assertion' % uri)
                sut.log(Result.NOT_TESTED, 'POST', r2.status_code, uri,
                        Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT, msg)
            # clean-up the created session
            if session_uri2 and loc1 != loc2:
                sut.session.delete(sut.rhost + session_uri2)
        else:
            msg = ('Second POST request to %s failed with status code %s'
                   % (uri, r2.status_code))
            sut.log(Result.WARN, 'POST', r2.status_code, uri,
                    Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT, msg)
        # clean-up the created session
        if session_uri1:
            sut.session.delete(sut.rhost + session_uri1)
    else:
        msg = ('POST request to %s failed with status code %s; unable to test '
               'this assertion' % (uri, r1.status_code))
        sut.log(Result.NOT_TESTED, 'POST', r1.status_code, uri,
                Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT, msg)


def test_delete_method_required(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_DELETE_METHOD_REQUIRED."""
    passed = False
    fail_uri, fail_response = None, None
    for uri, response in sut.get_responses_by_method('DELETE').items():
        if response.ok:
            sut.log(Result.PASS, 'DELETE', response.status_code, uri,
                    Assertion.REQ_DELETE_METHOD_REQUIRED, 'Test passed')
            passed = True
            break
        else:
            fail_uri, fail_response = uri, response

    if not passed:
        if fail_uri:
            msg = ('No successful DELETE responses found; extended error: %s'
                   % utils.get_extended_error(fail_response))
            sut.log(Result.FAIL, 'DELETE', fail_response.status_code, fail_uri,
                    Assertion.REQ_DELETE_METHOD_REQUIRED, msg)
        else:
            msg = 'No DELETE responses found; unable to test this assertion'
            sut.log(Result.NOT_TESTED, 'DELETE', '', '',
                    Assertion.REQ_DELETE_METHOD_REQUIRED, msg)


def test_delete_non_deletable_resource(sut: SystemUnderTest):
    """Perform tests for Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE."""
    passed = False
    warn_uri, warn_response = None, None
    fail_uri, fail_response = None, None
    for uri, response in sut.get_responses_by_method('DELETE',
                                                     request_type=RequestType.UNSUPPORTED_REQ).items():
        if response.status_code == requests.codes.METHOD_NOT_ALLOWED:
            sut.log(Result.PASS, 'DELETE', response.status_code, uri,
                    Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE, 'Test passed')
            passed = True
            break
        elif not response.ok:
            warn_uri, warn_response = uri, response
        else:
            fail_uri, fail_response = uri, response

    if not passed:
        if warn_uri or fail_uri:
            if fail_uri:
                msg = ('DELETE request for resource %s failed with status %s; '
                       'extended error: %s' %
                       (fail_uri, fail_response.status_code,
                        utils.get_extended_error(fail_response)))
                sut.log(Result.FAIL, 'DELETE', fail_response.status_code, fail_uri,
                        Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE, msg)
            else:
                msg = ('DELETE request for resource %s failed with status %s; '
                       'extended error: %s' %
                       (warn_uri, warn_response.status_code,
                        utils.get_extended_error(warn_response)))
                sut.log(Result.WARN, 'DELETE', warn_response.status_code, warn_uri,
                        Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE, msg)
        else:
            msg = ('No failed DELETE responses found; unable to test this '
                   'assertion')
            sut.log(Result.NOT_TESTED, 'DELETE', '', '',
                    Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE, msg)


def test_request_headers(sut: SystemUnderTest):
    """Perform tests from the 'Request headers' sub-section of the spec."""
    test_accept_header(sut)
    test_authorization_header(sut)
    test_content_type_header(sut)
    test_host_header(sut)
    test_if_match_header(sut)
    test_odata_version_header(sut)
    test_origin_header(sut)
    test_user_agent_header(sut)
    test_x_auth_token_header(sut)


def test_get(sut: SystemUnderTest):
    """Perform tests from the 'GET (read requests)' sub-section of the spec."""
    test_get_no_accept_header(sut)
    test_get_ignore_body(sut)
    test_get_collection_count_prop_required(sut)
    test_get_collection_count_prop_total(sut)
    test_get_service_root_url(sut)
    test_get_service_root_no_auth(sut)
    test_get_metadata_uri(sut)
    test_get_odata_uri(sut)
    test_get_metadata_odata_no_auth(sut)


def test_query_params(sut: SystemUnderTest):
    """Perform tests from the 'Query parameters' sub-section of the spec."""
    if not sut.supported_query_params:
        msg = ('No supported query parameters specified in the '
               'ProtocolFeaturesSupported object in the Service Root; '
               'unable to test query parameter assertions')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.REQ_QUERY_PROTOCOL_FEATURES_SUPPORTED, msg)
    else:
        test_query_ignore_unsupported(sut)
        test_query_unsupported_dollar_params(sut)
        test_query_invalid_values(sut)


def test_head(sut: SystemUnderTest):
    """Perform tests from the 'HEAD' sub-section of the spec."""
    test_head_differ_from_get(sut)


def test_data_modification(sut: SystemUnderTest):
    """Perform tests from the 'Data modification requests' sub-section of the
    spec."""
    test_data_mod_errors(sut)


def test_patch_update(sut: SystemUnderTest):
    """Perform tests from the 'PATCH (update)' sub-section of the spec."""
    test_patch_mixed_props(sut)
    test_patch_bad_prop(sut)
    test_patch_ro_resource(sut)
    test_patch_collection(sut)
    test_patch_odata_props(sut)


def test_patch_array_props(sut: SystemUnderTest):
    """Perform tests from the 'PATCH on array properties' sub-section of the
    spec."""
    orig_array = patch_array_save(sut)
    if orig_array is not None:
        test_patch_array_element_remove(sut)
        test_patch_array_element_unchanged(sut)
        test_patch_array_operations_order(sut)
        test_patch_array_truncate(sut)
        patch_array_restore(sut, orig_array)


def test_put(sut: SystemUnderTest):
    """Perform tests from the 'PUT (replace)' sub-section of the spec."""
    test_put_not_implemented(sut)


def test_post_create(sut: SystemUnderTest):
    """Perform tests from the 'POST (create)' sub-section of the spec."""
    test_post_create_via_collection(sut)
    test_post_create_uri_in_location_hdr(sut)
    test_post_create_to_members_prop(sut)
    test_post_create_not_supported(sut)
    test_post_create_not_idempotent(sut)


def test_delete(sut: SystemUnderTest):
    """Perform tests from the 'DELETE (delete)' sub-section of the spec."""
    test_delete_method_required(sut)
    test_delete_non_deletable_resource(sut)


def test_post_action(sut: SystemUnderTest):
    """Perform tests from the 'POST (Action)' sub-section of the spec."""
    # NOTE(bdodd): Actions better tested in the Redfish-Usecase-Checkers


def test_service_requests(sut: SystemUnderTest):
    """Perform tests from the 'Service requests' section of the spec."""
    test_request_headers(sut)
    test_get(sut)
    test_query_params(sut)
    test_head(sut)
    test_data_modification(sut)
    test_patch_update(sut)
    test_patch_array_props(sut)
    test_put(sut)
    test_post_create(sut)
    test_delete(sut)
    test_post_action(sut)
