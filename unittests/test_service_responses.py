# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions import service_responses as resp
from assertions.system_under_test import SystemUnderTest
from assertions.constants import Assertion, RequestType, ResourceType, Result
from unittests.utils import add_response, get_result


class ServiceResponses(TestCase):

    def setUp(self):
        super(ServiceResponses, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.sut.set_nav_prop_uri('Systems', '/redfish/v1/Systems')
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)

    def test_test_allow_header_method_not_allowed_not_tested(self):
        resp.test_allow_header_method_not_allowed(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No responses found that returned a %s status code' %
                      requests.codes.METHOD_NOT_ALLOWED, result['msg'])

    def test_test_allow_header_method_not_allowed_fail(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.METHOD_NOT_ALLOWED, headers={})
        resp.test_allow_header_method_not_allowed(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The Allow header was missing from response to %s '
                      'request to %s' % ('POST', uri), result['msg'])

    def test_test_allow_header_method_not_allowed_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.METHOD_NOT_ALLOWED,
                     headers={'Allow': 'GET, HEAD, PATCH'})
        resp.test_allow_header_method_not_allowed(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_ALLOW_METHOD_NOT_ALLOWED,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s'
                      % ('Allow', 'GET, HEAD, PATCH'), result['msg'])

    def test_test_allow_header_get_or_head_not_tested(self):
        uri = '/redfish/v1/'
        resp.test_allow_header_get_or_head(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD,
                            'HEAD', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found for %s request to %s' %
                      ('HEAD', uri), result['msg'])

    def test_test_allow_header_get_or_head_fail(self):
        uri = '/redfish/v1/'
        method = 'HEAD'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={})
        resp.test_allow_header_get_or_head(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the %s '
                      'request to URI %s' % ('Allow', method, uri),
                      result['msg'])

    def test_test_allow_header_get_or_head_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, 'GET', status_code=requests.codes.OK,
                     headers={'Allow': 'GET, HEAD, PATCH'})
        resp.test_allow_header_get_or_head(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ALLOW_GET_OR_HEAD,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s'
                      % ('Allow', 'GET, HEAD, PATCH'), result['msg'])

    def test_test_cache_control_header_not_tested1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        resp.test_cache_control_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CACHE_CONTROL,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, uri), result['msg'])

    def test_test_cache_control_header_not_tested2(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.NOT_FOUND, headers={})
        resp.test_cache_control_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CACHE_CONTROL,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, uri), result['msg'])

    def test_test_cache_control_header_fail(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={})
        resp.test_cache_control_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CACHE_CONTROL,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the %s '
                      'request to URI %s' % ('Cache-Control', method, uri),
                      result['msg'])

    def test_test_cache_control_header_pass(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={'Cache-Control': 'no-cache'})
        resp.test_cache_control_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CACHE_CONTROL,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s'
                      % ('Cache-Control', 'no-cache'), result['msg'])

    def test_test_content_type_header_not_tested1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        resp.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CONTENT_TYPE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, uri), result['msg'])

    def test_test_content_type_header_not_tested2(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.NOT_FOUND, headers={})
        resp.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CONTENT_TYPE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertEqual(requests.codes.NOT_FOUND, result['status'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, uri), result['msg'])

    def test_test_content_type_header_fail1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={})
        resp.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CONTENT_TYPE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the %s '
                      'request to URI %s' % ('Content-Type', method, uri),
                      result['msg'])

    def test_test_content_type_header_fail2(self):
        uri = '/redfish/v1/EventService/SSE'
        self.sut.set_server_sent_event_uri(uri)
        method = 'GET'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={'Content-Type': 'text/html'},
                     request_type=RequestType.STREAMING)
        resp.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CONTENT_TYPE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header value from the response to the %s '
                      'request to URI %s was %s; expected %s' %
                      ('Content-Type', method, uri, 'text/html',
                       'text/event-stream'), result['msg'])

    def test_test_content_type_header_pass(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={'Content-Type': 'application/json'})
        resp.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_CONTENT_TYPE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' %
                      ('Content-Type', 'application/json'), result['msg'])

    def test_test_etag_header_not_tested(self):
        uri = '/redfish/v1/AccountsService/Accounts/1'
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.NOT_FOUND,
                     res_type=ResourceType.MANAGER_ACCOUNT)
        resp.test_etag_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ETAG,
                            method, '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, 'ManagerAccount'), result['msg'])

    def test_test_etag_header_fail(self):
        uri = '/redfish/v1/AccountsService/Accounts/1'
        method = 'GET'
        r = add_response(self.sut, uri, method,
                         status_code=requests.codes.OK,
                         res_type=ResourceType.MANAGER_ACCOUNT)
        r.headers['ETag'] = None
        resp.test_etag_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ETAG,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the '
                      '%s request to URI %s' % ('ETag', method, uri),
                      result['msg'])

    def test_test_etag_header_pass(self):
        uri = '/redfish/v1/AccountsService/Accounts/1'
        method = 'GET'
        r = add_response(self.sut, uri, method,
                         status_code=requests.codes.OK,
                         res_type=ResourceType.MANAGER_ACCOUNT)
        r.headers['ETag'] = 'abcd1234'
        resp.test_etag_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ETAG,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' % ('ETag', 'abcd1234'),
                      result['msg'])

    def test_test_link_header_not_tested(self):
        uri = '/redfish/v1/'
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.NOT_FOUND)
        resp.test_link_header(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for %s request to %s' %
                      (method, uri), result['msg'])

    def test_test_link_header_fail1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        r = add_response(self.sut, uri, method,
                         status_code=requests.codes.OK,
                         headers={})
        r.links = {}
        resp.test_link_header(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The response did not include a Link header',
                      result['msg'])

    def test_test_link_header_fail2(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = '/redfish/v1/SchemaStore/en/ServiceRoot.json'
        r = add_response(
            self.sut, uri, method, status_code=requests.codes.OK,
            headers={'Link': '<%s>; rel=next' % uri_ref})
        r.links = {
            'next': {
                'url': uri_ref,
                'rel': 'next'
            }
        }
        resp.test_link_header(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The response included a Link header, but not one with '
                      'a rel=describedby param; %s: %s' %
                      ('Link', '<%s>; rel=next' % uri_ref), result['msg'])

    def test_test_link_header_pass(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = '/redfish/v1/SchemaStore/en/ServiceRoot.json'
        r = add_response(
            self.sut, uri, method, status_code=requests.codes.OK,
            headers={'Link': '<%s>; rel=describedby' % uri_ref})
        r.links = {
            'describedby': {
                'url': uri_ref,
                'rel': 'describedby'
            }
        }
        resp.test_link_header(self.sut)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_REL_DESCRIBED_BY,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' %
                      ('Link', '<%s>; rel=describedby' % uri_ref),
                      result['msg'])

    def test_test_link_header_schema_ver_match_fail1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = ''
        r = add_response(self.sut, uri, method,
                         status_code=requests.codes.OK)
        resp.test_link_header_schema_ver_match(
            self.sut, uri_ref, uri, method, r)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The Link header with a rel=describedby param did not '
                      'include a URI reference', result['msg'])

    def test_test_link_header_schema_ver_match_fail2(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = '/redfish/v1/SchemaStore/en/ServiceRoot.v1_5_0.json'
        odata_type = '#ServiceRoot.v1_5_1.ServiceRoot'
        r = add_response(self.sut, uri, method, status_code=requests.codes.OK,
                         json={'@odata.type': odata_type})
        resp.test_link_header_schema_ver_match(
            self.sut, uri_ref, uri, method, r)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Link header (%s) did not match the resource version '
                      'from the @odata.type property (%s)' %
                      (uri_ref, odata_type), result['msg'])

    def test_test_link_header_schema_ver_match_pass1(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = '/redfish/v1/SchemaStore/en/ServiceRoot.json'
        odata_type = '#ServiceRoot.v1_5_1.ServiceRoot'
        r = add_response(self.sut, uri, method, status_code=requests.codes.OK,
                         json={'@odata.type': odata_type})
        resp.test_link_header_schema_ver_match(
            self.sut, uri_ref, uri, method, r)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for unversioned resource %s' %
                      'ServiceRoot', result['msg'])

    def test_test_link_header_schema_ver_match_pass2(self):
        uri = '/redfish/v1/'
        method = 'GET'
        uri_ref = '/redfish/v1/SchemaStore/en/ServiceRoot.v1_5_1.json'
        odata_type = '#ServiceRoot.v1_5_1.ServiceRoot'
        r = add_response(self.sut, uri, method, status_code=requests.codes.OK,
                         json={'@odata.type': odata_type})
        resp.test_link_header_schema_ver_match(
            self.sut, uri_ref, uri, method, r)
        result = get_result(
            self.sut, Assertion.RESP_HEADERS_LINK_SCHEMA_VER_MATCH,
            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for versioned resource %s' %
                      'ServiceRoot.v1_5_1', result['msg'])

    def test_test_location_header_not_tested(self):
        method = 'POST'
        resp.test_location_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_LOCATION,
                            method, '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful POST (create) response found',
                      result['msg'])

    def test_test_location_header_fail1(self):
        method = 'POST'
        uri = '/redfish/v1/Foo'
        add_response(self.sut, uri, method, status_code=requests.codes.CREATED,
                     headers={})
        resp.test_location_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_LOCATION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the '
                      '%s request to URI %s' % ('Location', method, uri),
                      result['msg'])

    def test_test_location_header_fail2(self):
        method = 'POST'
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method, status_code=requests.codes.CREATED,
                     headers={'Location': uri + '/c123'})
        resp.test_location_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_LOCATION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the '
                      '%s request to URI %s' % ('X-Auth-Token', method, uri),
                      result['msg'])

    def test_test_location_header_pass(self):
        method = 'POST'
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method, status_code=requests.codes.CREATED,
                     headers={'Location': uri + '/c123',
                              'X-Auth-Token': '1a2b3c4'})
        resp.test_location_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_LOCATION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' %
                      ('X-Auth-Token', '1a2b3c4'), result['msg'])

    def test_test_odata_version_header_fail1(self):
        method = 'GET'
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={})
        resp.test_odata_version_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ODATA_VERSION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the '
                      '%s request to URI %s' % ('OData-Version', method, uri),
                      result['msg'])

    def test_test_odata_version_header_fail2(self):
        method = 'GET'
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={'OData-Version': '4.1'})
        resp.test_odata_version_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ODATA_VERSION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header value from the response to the '
                      '%s request to URI %s was %s; expected %s' %
                      ('OData-Version', method, uri, '4.1', '4.0'),
                      result['msg'])

    def test_test_odata_version_header_pass(self):
        method = 'GET'
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method, status_code=requests.codes.OK,
                     headers={'OData-Version': '4.0'})
        resp.test_odata_version_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_ODATA_VERSION,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' %
                      ('OData-Version', '4.0'), result['msg'])

    def test_test_www_authenticate_header_not_tested(self):
        resp.test_www_authenticate_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_WWW_AUTHENTICATE,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No 401 Unauthorized responses found', result['msg'])

    def test_test_www_authenticate_header_fail(self):
        uri = '/redfish/v1/Systems'
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH,
                     headers={})
        resp.test_www_authenticate_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_WWW_AUTHENTICATE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The %s header was missing from the response to the '
                      '%s request to URI %s' %
                      ('WWW-Authenticate', method, uri), result['msg'])

    def test_test_www_authenticate_header_pass(self):
        uri = self.sut.systems_uri
        method = 'GET'
        add_response(self.sut, uri, method,
                     status_code=requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH,
                     headers={'WWW-Authenticate': 'Basic'})
        resp.test_www_authenticate_header(self.sut)
        result = get_result(self.sut, Assertion.RESP_HEADERS_WWW_AUTHENTICATE,
                            method, uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header %s: %s' %
                      ('WWW-Authenticate', 'Basic'), result['msg'])

    def test_test_service_responses_cover(self):
        resp.test_service_responses(self.sut)


if __name__ == '__main__':
    unittest.main()
