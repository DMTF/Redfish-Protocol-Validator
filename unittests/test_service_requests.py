# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions import service_requests as req
from assertions.system_under_test import SystemUnderTest
from assertions.constants import Assertion, RequestType, Result
from unittests.utils import add_response, get_result


class ServiceRequests(TestCase):

    def setUp(self):
        super(ServiceRequests, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)
        self.sse_uri = '/redfish/v1/EventService/SSE'
        self.account_uri = '/redfish/v1/AccountsService/Accounts/3/'

    def test_test_accept_header_pass(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        add_response(self.sut, self.sse_uri, method='GET',
                     status_code=requests.codes.OK)
        req.test_accept_header(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEADERS_ACCEPT,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_accept_header_not_tested(self):
        uri = self.sse_uri
        self.sut.set_server_sent_event_uri(self.sse_uri)
        response = add_response(self.sut, uri, method='GET',
                                status_code=requests.codes.NOT_FOUND)
        self.mock_session.get.return_value = response
        req.test_accept_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_ACCEPT, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Resource at URI %s not found' % uri,
                      result['msg'])

    def test_test_accept_header_fail(self):
        uri = '/redfish/v1/openapi.yaml'
        response = add_response(self.sut, uri, method='GET',
                                status_code=requests.codes.NOT_ACCEPTABLE)
        self.mock_session.get.return_value = response
        req.test_accept_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_ACCEPT, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to %s failed with status code %s using '
                      'header Accept:' % (uri, requests.codes.NOT_ACCEPTABLE),
                      result['msg'])

    def test_test_authorization_header_not_tested(self):
        req.test_authorization_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_AUTHORIZATION,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response using a basic authentication header found',
                      result['msg'])

    def test_test_authorization_header_warn(self):
        r = add_response(self.sut, self.sut.sessions_uri, method='GET',
                         status_code=requests.codes.OK,
                         request_type=RequestType.BASIC_AUTH)
        r.request.headers = {}
        req.test_authorization_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_AUTHORIZATION,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('Expected basic authentication request to include an '
                      'Authorization header', result['msg'])

    def test_test_authorization_header_fail(self):
        r = add_response(self.sut, self.sut.sessions_uri, method='GET',
                         status_code=requests.codes.UNAUTHORIZED,
                         request_type=RequestType.BASIC_AUTH)
        r.request.headers = {'Authorization': 'xyz'}
        req.test_authorization_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_AUTHORIZATION,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Basic authentication request with Authorization header '
                      'to protected URI failed', result['msg'])

    def test_test_authorization_header_pass(self):
        r = add_response(self.sut, self.sut.sessions_uri, method='GET',
                         status_code=requests.codes.OK,
                         request_type=RequestType.BASIC_AUTH)
        r.request.headers = {'Authorization': 'xyz'}
        req.test_authorization_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_AUTHORIZATION,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_content_type_header_not_tested(self):
        req.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_CONTENT_TYPE,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful PATCH or POST response found',
                      result['msg'])

    def test_test_content_type_header_pass(self):
        r = add_response(self.sut, self.sut.sessions_uri, method='POST',
                         status_code=requests.codes.CREATED)
        r.request.headers = {'Content-Type': 'application/json'}
        req.test_content_type_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_CONTENT_TYPE,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header Content-Type: application/json',
                      result['msg'])

    def test_test_host_header_not_tested1(self):
        uri = '/redfish/v1/'
        req.test_host_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_HOST, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response for GET request to URI %s found' % uri,
                      result['msg'])

    def test_test_host_header_not_tested2(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.NOT_FOUND)
        req.test_host_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_HOST, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('GET request to URI %s was not successful' % uri,
                      result['msg'])
        self.assertIn('unable to test this assertion for header Host',
                      result['msg'])

    def test_test_host_header_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK)
        req.test_host_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_HOST, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header Host', result['msg'])

    def test_test_if_match_header_not_tested1(self):
        r = add_response(self.sut, self.account_uri, method='PATCH',
                         status_code=requests.codes.PRECONDITION_FAILED,
                         request_type=RequestType.BAD_ETAG)
        r.request.headers = {'If-Match': 'abc123'}
        req.test_if_match_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_IF_MATCH, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful PATCH response using If-Match',
                      result['msg'])

    def test_test_if_match_header_not_tested2(self):
        r = add_response(self.sut, self.account_uri, method='PATCH',
                         status_code=requests.codes.OK)
        r.request.headers = {'If-Match': 'abc123'}
        req.test_if_match_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_IF_MATCH, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH response using incorrect If-Match',
                      result['msg'])

    def test_test_if_match_header_pass(self):
        r1 = add_response(self.sut, self.account_uri, method='PATCH',
                          status_code=requests.codes.OK)
        r1.request.headers = {'If-Match': 'abc123'}
        r2 = add_response(self.sut, self.account_uri, method='PATCH',
                          status_code=requests.codes.PRECONDITION_FAILED,
                          request_type=RequestType.BAD_ETAG)
        r2.request.headers = {'If-Match': 'abc123'}
        req.test_if_match_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_IF_MATCH,
                            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for unsuccessful If-Match header',
                      result['msg'])

    def test_test_odata_version_header_pass(self):
        uri = '/redfish/v1/'
        r1 = add_response(self.sut, uri, method='GET',
                          status_code=requests.codes.OK)
        r1.request.headers = {'OData-Version': '4.0'}
        r2 = add_response(self.sut, uri, method='GET',
                          status_code=requests.codes.PRECONDITION_FAILED)
        r2.request.headers = {'OData-Version': '4.1'}
        self.mock_session.get.side_effect = [r1, r2]
        req.test_odata_version_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_ODATA_VERSION,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for unsupported header OData-Version: 4.1',
                      result['msg'])

    def test_test_odata_version_header_fail(self):
        uri = '/redfish/v1/'
        r1 = add_response(self.sut, uri, method='GET',
                          status_code=requests.codes.BAD_REQUEST)
        r1.request.headers = {'OData-Version': '4.0'}
        r2 = add_response(self.sut, uri, method='GET',
                          status_code=requests.codes.BAD_REQUEST)
        r2.request.headers = {'OData-Version': '4.1'}
        self.mock_session.get.side_effect = [r1, r2]
        req.test_odata_version_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_ODATA_VERSION,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Request with unsupported header OData-Version: 4.1 '
                      'returned status %s; expected status %s' % (
                       requests.codes.BAD_REQUEST,
                       requests.codes.PRECONDITION_FAILED),
                      result['msg'])

    def test_test_user_agent_header_not_tested1(self):
        uri = '/redfish/v1/'
        req.test_user_agent_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_USER_AGENT,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response for GET request to URI %s found'
                      % uri, result['msg'])

    def test_test_user_agent_header_not_tested2(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        r.request.headers = {}
        req.test_user_agent_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_USER_AGENT,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No User-Agent header found in request', result['msg'])

    def test_test_user_agent_header_pass(self):
        uri = '/redfish/v1/'
        agent = 'python-requests/2.23.0'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        r.request.headers = {'User-Agent': agent}
        req.test_user_agent_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_USER_AGENT,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header User-Agent: %s' % agent,
                      result['msg'])

    def test_test_x_auth_token_header_not_tested1(self):
        uri = self.sut.sessions_uri
        req.test_x_auth_token_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_X_AUTH_TOKEN,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response for GET request to URI %s found'
                      % uri, result['msg'])

    def test_test_x_auth_token_header_not_tested2(self):
        uri = self.sut.sessions_uri
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        r.request.headers = {}
        req.test_x_auth_token_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_X_AUTH_TOKEN,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No X-Auth-Token header found in request', result['msg'])

    def test_test_x_auth_token_header_pass(self):
        uri = self.sut.sessions_uri
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        r.request.headers = {'X-Auth-Token': '1234567890abcdef'}
        req.test_x_auth_token_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_HEADERS_X_AUTH_TOKEN,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed for header X-Auth-Token', result['msg'])

    def test_test_get_no_accept_header_fail1(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.NOT_ACCEPTABLE)
        self.mock_session.get.return_value = r
        req.test_get_no_accept_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_GET_NO_ACCEPT_HEADER,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to URI %s with no Accept header failed'
                      % uri, result['msg'])

    def test_test_get_no_accept_header_fail2(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK,
                         headers={'Content-Type': 'text/html'})
        self.mock_session.get.return_value = r
        req.test_get_no_accept_header(self.sut)
        result = get_result(self.sut, Assertion.REQ_GET_NO_ACCEPT_HEADER,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('contained a Content-Type of %s; expected %s'
                      % ('text/html', 'application/json'), result['msg'])

    def test_test_get_no_accept_header_pass(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK,
                         headers={'Content-Type': 'application/json'})
        self.mock_session.get.return_value = r
        req.test_get_no_accept_header(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_NO_ACCEPT_HEADER,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_ignore_body_fail(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.BAD_REQUEST)
        self.mock_session.get.return_value = r
        req.test_get_ignore_body(self.sut)
        result = get_result(self.sut, Assertion.REQ_GET_IGNORE_BODY,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to URI %s that included a body failed'
                      % uri, result['msg'])

    def test_test_get_ignore_body_pass(self):
        uri = '/redfish/v1/'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        self.mock_session.get.return_value = r
        req.test_get_ignore_body(self.sut)
        result = get_result(self.sut, Assertion.REQ_GET_IGNORE_BODY,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_collection_count_prop_required_not_tested(self):
        uri = self.sut.sessions_uri
        req.test_get_collection_count_prop_required(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Successful response for GET request to URI %s not found'
                      % uri, result['msg'])

    def test_test_get_collection_count_prop_required_fail1(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={})
        req.test_get_collection_count_prop_required(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The collection resource at URI %s did not include'
                      % uri, result['msg'])

    def test_test_get_collection_count_prop_required_fail2(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': '3'})
        req.test_get_collection_count_prop_required(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The count property was present but the type was str; '
                      'expected int', result['msg'])

    def test_test_get_collection_count_prop_required_pass(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 3})
        req.test_get_collection_count_prop_required(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_REQUIRED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_collection_count_prop_total_not_tested(self):
        uri = self.sut.sessions_uri
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Successful response for GET request to URI %s not found'
                      % uri, result['msg'])

    def test_test_get_collection_count_prop_total_fail1(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The collection resource at URI %s did not include the '
                      'required count property'
                      % uri, result['msg'])

    def test_test_get_collection_count_prop_total_fail2(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 2})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The collection resource at URI %s did not include the '
                      'Members property'
                      % uri, result['msg'])

    def test_test_get_collection_count_prop_total_fail3(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 3, 'Members': [{}, {}]})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Collection resource %s did not contain a next link '
                      % uri, result['msg'])
        self.assertIn('the count property (3) was not equal to the number of '
                      'members in the resource (2)', result['msg'])

    def test_test_get_collection_count_prop_total_fail4(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 3, 'Members': [{}, {}, {}],
                           'Members@odata.nextLink': '/foo/bar'})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Collection resource %s contained a next link property'
                      % uri, result['msg'])
        self.assertIn('the count property (3) was less than or equal to the '
                      'number of members in the original resource (3)',
                      result['msg'])

    def test_test_get_collection_count_prop_total_pass1(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 2, 'Members': [{}, {}]})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_collection_count_prop_total_pass2(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     json={'Members@odata.count': 4, 'Members': [{}, {}, {}],
                           'Members@odata.nextLink': '/foo/bar'})
        req.test_get_collection_count_prop_total(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_COLLECTION_COUNT_PROP_TOTAL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_service_root_url_not_tested(self):
        uri = '/redfish/v1/'
        req.test_get_service_root_url(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_URL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response for GET request to Service Root URL %s not '
                      'found' % uri, result['msg'])

    def test_test_get_service_root_url_fail(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.NOT_FOUND)
        req.test_get_service_root_url(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_URL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to Service Root URL %s failed with status '
                      'code %s' % (uri, requests.codes.NOT_FOUND),
                      result['msg'])

    def test_test_get_service_root_url_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK)
        req.test_get_service_root_url(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_URL,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_service_root_no_auth_not_tested(self):
        uri = '/redfish/v1/'
        req.test_get_service_root_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response for GET request with no authentication to '
                      'URL %s not found' % uri, result['msg'])

    def test_test_get_service_root_no_auth_fail(self):
        uri = '/redfish'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        req.test_get_service_root_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request with no authentication to URL '
                      '%s failed with status code %s' %
                      (uri, requests.codes.UNAUTHORIZED), result['msg'])

    def test_test_get_service_root_no_auth_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        req.test_get_service_root_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_SERVICE_ROOT_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_metadata_uri_not_tested(self):
        uri = '/redfish/v1/$metadata'
        req.test_get_metadata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response for GET request to metadata URI %s not '
                      'found' % uri, result['msg'])

    def test_test_get_metadata_uri_fail(self):
        uri = '/redfish/v1/$metadata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.NOT_FOUND)
        req.test_get_metadata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to metadata URI %s failed with status '
                      'code %s' % (uri, requests.codes.NOT_FOUND),
                      result['msg'])

    def test_test_get_metadata_uri_pass(self):
        uri = '/redfish/v1/$metadata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK)
        req.test_get_metadata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_odata_uri_not_tested(self):
        uri = '/redfish/v1/odata'
        req.test_get_odata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_ODATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response for GET request to OData URI %s not '
                      'found' % uri, result['msg'])

    def test_test_get_odata_uri_fail(self):
        uri = '/redfish/v1/odata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.NOT_FOUND)
        req.test_get_odata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_ODATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request to OData URI %s failed with status '
                      'code %s' % (uri, requests.codes.NOT_FOUND),
                      result['msg'])

    def test_test_get_odata_uri_pass(self):
        uri = '/redfish/v1/odata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK)
        req.test_get_odata_uri(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_ODATA_URI,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_get_metadata_odata_no_auth_not_tested(self):
        uri = '/redfish/v1/$metadata'
        req.test_get_metadata_odata_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_ODATA_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response for GET request with no authentication to '
                      'URI %s not found' % uri, result['msg'])

    def test_test_get_metadata_odata_no_auth_fail(self):
        uri = '/redfish/v1/odata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        req.test_get_metadata_odata_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_ODATA_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request with no authentication to URI '
                      '%s failed with status code %s' %
                      (uri, requests.codes.UNAUTHORIZED), result['msg'])

    def test_test_get_metadata_odata_no_auth_pass(self):
        uri = '/redfish/v1/$metadata'
        add_response(self.sut, uri, method='GET',
                     status_code=requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        req.test_get_metadata_odata_no_auth(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_GET_METADATA_ODATA_NO_AUTH,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_service_requests_cover(self):
        req.test_service_requests(self.sut)


if __name__ == '__main__':
    unittest.main()
