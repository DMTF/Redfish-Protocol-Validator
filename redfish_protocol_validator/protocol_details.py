# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, ResourceType, RequestType, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

safe_chars_regex = re.compile(
    r"^([A-Za-z0-9!$&'()*+,\-./:;=@_]|%[A-Fa-f0-9]{2})*\Z")
encoded_char_regex = re.compile(r"%[A-Fa-f0-9]{2}")

# See RFC 7232, section 2.3 Etags - valid chars within the double quotes
#   of the opaque-tag can be 0x21, 0x23-0x7F, 0x80-0xFF
etag_regex = re.compile(r'^(W/)?"[\x21\x23-\xFF]*"$')


def split_path(uri):
    """
    Split the URI into path[?query][#fragment]

    :param uri: the URI to split
    :return: tuple of path, query, fragment
    """
    parsed = urlparse(uri)
    return parsed.path, parsed.query, parsed.fragment


def safe_uri(uri):
    """
    Determine if URI is safe (does not use RFC 1738 unsafe character)

    :param uri: URI to check
    :return: True if URI is safe, False otherwise
    """
    path, query, frag = split_path(uri)
    safe = True
    for part in (path, query, frag):
        safe = safe and safe_chars_regex.search(part)
    return safe


def encoded_char_in_uri(uri):
    """
    Determine if path or frag of URI contain any percent-encoded characters

    :param uri: URI to check
    :return: True if encoded chars found in path or frag, False otherwise
    """
    path, query, frag = split_path(uri)
    encoded = False
    for part in (path, frag):
        encoded = encoded or encoded_char_regex.search(part)
    return encoded


def check_relative_ref(uri):
    result = Result.PASS
    msg = 'Test passed'
    parsed = urlparse(uri)
    if uri.startswith('///'):
        result = Result.FAIL
        msg = ('Relative reference %s should not start with a triple '
               'forward slash (///)' % uri)
    elif uri.startswith('//'):
        if not parsed.netloc:
            result = Result.FAIL
            msg = ('Relative reference %s does not include the expected '
                   'authority (network-path)' % uri)
        elif not parsed.path:
            result = Result.FAIL
            msg = ('Relative reference %s does not include the expected '
                   'absolute-path' % uri)
    return result, msg


def response_is_json(uri, response):
    result = Result.PASS
    msg = 'Test passed'
    if response.status_code in [requests.codes.OK, requests.codes.CREATED]:
        try:
            response.json()
        except ValueError as e:
            result = Result.FAIL
            msg = ('%s request to URI %s did not return JSON response: %s' %
                   (response.request.method, uri, repr(e)))
    else:
        result = Result.FAIL
        msg = ('%s request to URI %s received status %s' %
               (response.request.method, uri, response.status_code))
    return result, msg


def response_content_type_is_json(uri, response):
    header = response.headers.get('Content-Type', '')
    media_type = utils.get_response_media_type(response)
    if media_type == 'application/json':
        return Result.PASS, 'Test passed'
    else:
        msg = ('%s request to URI %s received Content-Type header "%s"; '
               'expected media type "application/json"' %
               (response.request.method, uri, header))
        return Result.FAIL, msg


def check_slash_redfish(uri, response):
    expected = {"v1": "/redfish/v1/"}
    result, msg = response_is_json(uri, response)
    if result == Result.PASS:
        if response.json() != expected:
            result = Result.FAIL
            msg = ('Content of %s resource contained %s; expected %s' %
                   (uri, response.json(), expected))
    return result, msg


def response_is_xml(uri, response):
    result = Result.PASS
    msg = 'Test passed'
    if response.status_code == requests.codes.OK:
        try:
            ET.fromstring(response.text)
        except ET.ParseError as e:
            result = Result.FAIL
            msg = ('%s request to URI %s did not return XML response: %s' %
                   (response.request.method, uri, repr(e)))
    else:
        result = Result.FAIL
        msg = ('%s request to URI %s received status %s' %
               (response.request.method, uri, response.status_code))
    return result, msg


def check_etag_present(uri, response):
    etag = response.headers.get('ETag')
    if etag:
        return Result.PASS, 'Test passed'
    else:
        msg = ('Response from %s request to ManagerAccount URI %s did not '
               'return an ETag header' % (response.request.method, uri))
        return Result.FAIL, msg


def check_etag_valid(etag):
    return bool(etag_regex.search(etag))


def test_uri(sut: SystemUnderTest, uri, response):
    """Perform tests on the URI format and encoding."""

    # Test Assertion.PROTO_URI_SAFE_CHARS
    safe = safe_uri(uri)
    result = Result.PASS if safe else Result.FAIL
    msg = 'Test passed' if safe else 'URI contains one or more unsafe chars'
    sut.log(result, response.request.method, response.status_code, uri,
            Assertion.PROTO_URI_SAFE_CHARS, msg)

    # Test Assertion.PROTO_URI_NO_ENCODED_CHARS
    encoded = encoded_char_in_uri(uri)
    result = Result.PASS if not encoded else Result.FAIL
    msg = ('Test passed' if not encoded else
           'URI contains one or more percent-encoded chars')
    sut.log(result, response.request.method, response.status_code, uri,
            Assertion.PROTO_URI_NO_ENCODED_CHARS, msg)

    # Test Assertion.PROTO_URI_RELATIVE_REFS
    result, msg = check_relative_ref(uri)
    sut.log(result, response.request.method, response.status_code, uri,
            Assertion.PROTO_URI_RELATIVE_REFS, msg)


def test_http_supported_methods(sut: SystemUnderTest):
    """Perform tests on the supported HTTP methods."""
    # Test Assertion.PROTO_HTTP_SUPPORTED_METHODS
    for method in ['GET', 'POST', 'PATCH', 'DELETE']:
        responses = sut.get_responses_by_method(method)
        if not responses:
            sut.log(Result.NOT_TESTED, method, '', '',
                    Assertion.PROTO_HTTP_SUPPORTED_METHODS,
                    '%s not tested' % method)
            continue
        passed = False
        for uri, response in responses.items():
            if 200 <= response.status_code < 300:
                sut.log(Result.PASS, method, response.status_code, '',
                        Assertion.PROTO_HTTP_SUPPORTED_METHODS,
                        '%s supported' % method)
                passed = True
                break
        if not passed:
            sut.log(Result.FAIL, method, '', '',
                    Assertion.PROTO_HTTP_SUPPORTED_METHODS,
                    'No %s requests had a successful response' % method)


def test_http_unsupported_methods(sut: SystemUnderTest):
    """Perform tests on unsupported HTTP methods."""
    # Test Assertion.PROTO_HTTP_UNSUPPORTED_METHODS
    uri = '/redfish/v1/'
    response = sut.get_response('DELETE', uri, request_type=RequestType.UNSUPPORTED_REQ)
    if response is None:
        sut.log(Result.NOT_TESTED, 'DELETE', '', uri,
                Assertion.PROTO_HTTP_UNSUPPORTED_METHODS,
                'No response found for DELETE method request')
    elif (response.status_code == requests.codes.METHOD_NOT_ALLOWED or
          response.status_code == requests.codes.NOT_IMPLEMENTED):
        sut.log(Result.PASS, 'DELETE', response.status_code, uri,
                Assertion.PROTO_HTTP_UNSUPPORTED_METHODS, 'Test passed')
    else:
        sut.log(Result.FAIL, 'DELETE', response.status_code, uri,
                Assertion.PROTO_HTTP_UNSUPPORTED_METHODS,
                'DELETE method returned status %s; expected status %s' %
                (response.status_code, requests.codes.METHOD_NOT_ALLOWED))


def test_media_types(sut: SystemUnderTest, uri, response):
    """Perform tests of the supported media types."""
    if (uri != '/redfish/v1/$metadata' and response.request.method != 'HEAD'
            and response.status_code in [requests.codes.OK,
                                         requests.codes.CREATED]):
        if (response.status_code == requests.codes.CREATED and response.request.method == 'POST' and
                len(response.text) == 0):
            sut.log(Result.NOT_TESTED, response.request.method, response.status_code, uri,
                    Assertion.PROTO_JSON_ALL_RESOURCES, 'No response body')
            sut.log(Result.NOT_TESTED, response.request.method, response.status_code, uri,
                    Assertion.PROTO_JSON_RFC, 'No response body')
        else:
            # Test Assertion.PROTO_JSON_ALL_RESOURCES
            result, msg = response_content_type_is_json(uri, response)
            sut.log(result, response.request.method, response.status_code, uri,
                    Assertion.PROTO_JSON_ALL_RESOURCES, msg)

            # Test Assertion.PROTO_JSON_RFC
            result, msg = response_is_json(uri, response)
            sut.log(result, response.request.method, response.status_code, uri,
                    Assertion.PROTO_JSON_RFC, msg)

    # Test Assertion.PROTO_JSON_ACCEPTED
    if response.request.body:
        if response.status_code in [requests.codes.OK, requests.codes.CREATED,
                                    requests.codes.NOT_ACCEPTABLE,
                                    requests.codes.UNSUPPORTED_MEDIA_TYPE]:
            if (response.status_code == requests.codes.CREATED and response.request.method == 'POST' and
                    len(response.text) == 0):
                sut.log(Result.NOT_TESTED, response.request.method, response.status_code, uri,
                        Assertion.PROTO_JSON_ACCEPTED, 'No response body')
            else:
                result, msg = response_is_json(uri, response)
                sut.log(result, response.request.method, response.status_code,
                        uri, Assertion.PROTO_JSON_ACCEPTED, msg)


def test_valid_etag(sut: SystemUnderTest, uri, response):
    """Perform tests for RFC7232 ETag support."""
    # Test Assertion.PROTO_ETAG_RFC7232
    if (response.request.method != 'HEAD' and response.status_code
            in [requests.codes.OK, requests.codes.CREATED]):
        etag = response.headers.get('ETag')
        source = 'header'
        if (etag is None and utils.get_response_media_type(response)
                == 'application/json'):
            data = response.json()
            if '@odata.etag' in data:
                source = 'property'
                etag = data.get('@odata.etag')
        if etag is not None:
            if check_etag_valid(etag):
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.PROTO_ETAG_RFC7232, 'Test passed')
            else:
                msg = ('Response from %s request to URI %s returned invalid '
                       'ETag %s value %s'
                       % (response.request.method, uri, source, etag))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, uri,
                        Assertion.PROTO_ETAG_RFC7232, msg)


def test_account_etags(sut: SystemUnderTest):
    """Perform tests for ETag support on ManagerAccount GET."""
    # Test Assertion.PROTO_ETAG_ON_GET_ACCOUNT
    responses = sut.get_responses_by_method(
        'GET', resource_type=ResourceType.MANAGER_ACCOUNT)
    for uri, response in responses.items():
        if response.status_code == requests.codes.OK:
            result, msg = check_etag_present(uri, response)
            sut.log(result, response.request.method, response.status_code, uri,
                    Assertion.PROTO_ETAG_ON_GET_ACCOUNT, msg)


def test_standard_uris(sut: SystemUnderTest, uri, response):
    """Perform tests on the standard, spec-defined URIs."""

    if response.request.method == 'GET':
        # Test Assertion.PROTO_STD_URI_SERVICE_ROOT
        if uri == '/redfish/v1/':
            result, msg = response_is_json(uri, response)
            sut.log(result, response.request.method, response.status_code,
                    uri, Assertion.PROTO_STD_URI_SERVICE_ROOT, msg)

        # Test Assertion.PROTO_STD_URI_VERSION
        if uri == '/redfish':
            result, msg = check_slash_redfish(uri, response)
            sut.log(result, response.request.method, response.status_code,
                    uri, Assertion.PROTO_STD_URI_VERSION, msg)

        # Test Assertion.PROTO_STD_URIS_SUPPORTED
        if uri in ['/redfish', '/redfish/v1/', '/redfish/v1/odata']:
            result, msg = response_is_json(uri, response)
            sut.log(result, response.request.method, response.status_code,
                    uri, Assertion.PROTO_STD_URIS_SUPPORTED, msg)
        if uri == '/redfish/v1/$metadata':
            result, msg = response_is_xml(uri, response)
            sut.log(result, response.request.method, response.status_code,
                    uri, Assertion.PROTO_STD_URIS_SUPPORTED, msg)

        # Test Assertion.PROTO_STD_URI_SERVICE_ROOT_REDIRECT
        if uri == '/redfish/v1':
            result, msg = response_is_json(uri, response)
            sut.log(result, response.request.method, response.status_code,
                    uri, Assertion.PROTO_STD_URI_SERVICE_ROOT_REDIRECT, msg)


def test_protocol_details(sut: SystemUnderTest):
    """Perform tests from the 'Protocol details' section of the spec."""
    for uri, response in sut.get_all_responses():
        test_uri(sut, uri, response)
        test_media_types(sut, uri, response)
        test_valid_etag(sut, uri, response)
        test_standard_uris(sut, uri, response)
    test_http_supported_methods(sut)
    test_http_unsupported_methods(sut)
    test_account_etags(sut)
