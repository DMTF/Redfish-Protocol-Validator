# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from redfish_protocol_validator import service_requests as req
from redfish_protocol_validator.system_under_test import SystemUnderTest
from redfish_protocol_validator.constants import Assertion, RequestType, Result
from unittests.utils import add_response, get_result


class ServiceRequests(TestCase):

    def setUp(self):
        super(ServiceRequests, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)
        self.sse_uri = '/redfish/v1/EventService/SSE'
        self.accounts_uri = '/redfish/v1/AccountsService/Accounts'
        self.account_uri = self.accounts_uri + '/3'
        self.sut.set_supported_query_params({'ExcerptQuery': True})
        self.mgr_net_proto_uri = '/redfish/v1/Managers/BMC/NetworkProtocol'
        self.sut.set_mgr_net_proto_uri(self.mgr_net_proto_uri)
        self.sut.set_nav_prop_uri('Accounts', self.accounts_uri)
        add_response(self.sut, self.mgr_net_proto_uri, 'GET',
                     json={'NTP': {'NTPServers': ['', '', ''],
                                   'ProtocolEnabled': False}})

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

    def test_test_accept_header_exception(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        r = add_response(self.sut, self.sse_uri, method='GET',
                         status_code=requests.codes.OK)
        # first 19 GETs return a result, 20th gets a ConnectionError
        self.mock_session.get.side_effect = [r] * 19 + [ConnectionError]
        req.test_accept_header(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEADERS_ACCEPT,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Caught ConnectionError while opening SSE',
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

    def test_test_query_params_not_tested(self):
        self.sut.set_supported_query_params({})
        req.test_query_params(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_PROTOCOL_FEATURES_SUPPORTED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No supported query parameters specified in the '
                      'ProtocolFeaturesSupported object in the Service Root',
                      result['msg'])

    def test_test_query_ignore_unsupported_fail(self):
        uri = '/redfish/v1/?rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.NOT_IMPLEMENTED)
        self.mock_session.get.return_value = r
        req.test_query_ignore_unsupported(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_IGNORE_UNSUPPORTED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('GET request with unknown query parameter (URI %s) '
                      'failed' % uri, result['msg'])

    def test_test_query_ignore_unsupported_pass(self):
        uri = '/redfish/v1/?rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        self.mock_session.get.return_value = r
        req.test_query_ignore_unsupported(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_IGNORE_UNSUPPORTED,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_query_unsupported_dollar_params_fail(self):
        uri = '/redfish/v1/?$rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.BAD_REQUEST)
        self.mock_session.get.return_value = r
        req.test_query_unsupported_dollar_params(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('query parameter that starts with $ (URI %s) returned '
                      'status %s; expected status %s' %
                      (uri, requests.codes.BAD_REQUEST,
                       requests.codes.NOT_IMPLEMENTED), result['msg'])

    def test_test_query_unsupported_dollar_params_pass(self):
        uri = '/redfish/v1/?$rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.NOT_IMPLEMENTED,
                         json={'error': {'@Message.ExtendedInfo': [
                                 {'Message': '$rpvunknown not supported'}
                         ]}})
        self.mock_session.get.return_value = r
        req.test_query_unsupported_dollar_params(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        """
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        """

    def test_test_query_unsupported_dollar_params_mixed1(self):
        uri = '/redfish/v1/?$rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.NOT_IMPLEMENTED,
                         json={})
        self.mock_session.get.return_value = r
        req.test_query_unsupported_dollar_params(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        """
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The response did not contain an extended error',
                      result['msg'])
        """

    def test_test_query_unsupported_dollar_params_mixed2(self):
        uri = '/redfish/v1/?$rpvunknown'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.NOT_IMPLEMENTED,
                         json={'@Message.ExtendedInfo': [
                             {'Message': 'parameter not supported'}
                         ]})
        self.mock_session.get.return_value = r
        req.test_query_unsupported_dollar_params(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_DOLLAR_PARAMS,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        """
        result = get_result(
            self.sut, Assertion.REQ_QUERY_UNSUPPORTED_PARAMS_EXT_ERROR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The response contained an extended error, but the '
                      'unsupported query parameter', result['msg'])
        """

    def test_test_query_invalid_values_not_tested(self):
        self.sut.set_supported_query_params({})
        req.test_query_invalid_values(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_INVALID_VALUES, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('The service does not support either the \'only\' or '
                      '\'excerpt\' query parameters', result['msg'])

    def test_test_query_invalid_values_fail(self):
        uri = '/redfish/v1/' + '?excerpt=foo'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.OK)
        self.mock_session.get.return_value = r
        req.test_query_invalid_values(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_INVALID_VALUES, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('invalid query parameter (URI %s) returned status %s; '
                      'expected status %s' % (
                       uri, requests.codes.OK, requests.codes.BAD_REQUEST),
                      result['msg'])

    def test_test_query_invalid_values_pass(self):
        self.sut.set_supported_query_params({'OnlyMemberQuery': True})
        uri = self.sut.sessions_uri + '?only=foo'
        r = add_response(self.sut, uri, method='GET',
                         status_code=requests.codes.BAD_REQUEST)
        self.mock_session.get.return_value = r
        req.test_query_invalid_values(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_QUERY_INVALID_VALUES, 'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_head_differ_from_get_pass(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='HEAD',
                     status_code=requests.codes.OK)
        req.test_head_differ_from_get(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEAD_DIFFERS_FROM_GET, 'HEAD', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_head_differ_from_get_not_tested(self):
        uri = '/redfish/v1/'
        req.test_head_differ_from_get(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEAD_DIFFERS_FROM_GET, 'HEAD', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No HEAD request to uri %s found' % uri, result['msg'])

    def test_test_head_differ_from_get_fail1(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='HEAD',
                     status_code=requests.codes.OK,
                     json={})
        req.test_head_differ_from_get(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEAD_DIFFERS_FROM_GET, 'HEAD', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('HEAD request to uri %s returned a non-empty body '
                      '(Content-Type: application/json; Content-Length: 2)'
                      % uri, result['msg'])

    def test_test_head_differ_from_get_fail2(self):
        uri = '/redfish/v1/'
        add_response(self.sut, uri, method='HEAD',
                     status_code=requests.codes.BAD_REQUEST)
        req.test_head_differ_from_get(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_HEAD_DIFFERS_FROM_GET, 'HEAD', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('HEAD request to uri %s failed with status %s' %
                      (uri, requests.codes.BAD_REQUEST),
                      result['msg'])

    def test_test_data_mod_errors_not_tested(self):
        uri = self.sut.sessions_uri
        r = add_response(self.sut, uri, method='POST',
                         status_code=requests.codes.CREATED,
                         headers={'Location': uri + '/xyz'})
        self.mock_session.head.return_value = r
        req.test_data_mod_errors(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DATA_MOD_ERRORS, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No failed POST responses found; unable to test this '
                      'assertion', result['msg'])

    def test_test_data_mod_errors_pass(self):
        uri = self.sut.sessions_uri
        r = add_response(self.sut, uri, method='POST',
                         status_code=requests.codes.BAD_REQUEST)
        self.mock_session.head.return_value = r
        req.test_data_mod_errors(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DATA_MOD_ERRORS, 'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_data_mod_errors_fail(self):
        uri = self.sut.sessions_uri
        r = add_response(self.sut, uri, method='POST',
                         status_code=requests.codes.BAD_REQUEST,
                         headers={'Location': uri + '/xyz'})
        self.mock_session.head.return_value = r
        req.test_data_mod_errors(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DATA_MOD_ERRORS, 'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('uri %s failed with status %s, but appeared to create '
                      'resource %s' % (uri, requests.codes.BAD_REQUEST,
                                       uri + '/xyz'), result['msg'])

    def test_test_patch_mixed_props_not_tested(self):
        req.test_patch_mixed_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_MIXED_PROPS, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH responses found for this condition; unable to '
                      'test this assertion', result['msg'])

    def test_test_patch_mixed_props_fail1(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.FORBIDDEN,
                     request_type=RequestType.PATCH_MIXED_PROPS)
        req.test_patch_mixed_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_MIXED_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response returned status code %s; expected '
                      '%s' % (requests.codes.FORBIDDEN, requests.codes.OK),
                      result['msg'])

    def test_test_patch_mixed_props_fail2(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.OK,
                     request_type=RequestType.PATCH_MIXED_PROPS,
                     json={'error': {}})
        req.test_patch_mixed_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_MIXED_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response did not include the resource '
                      'representation', result['msg'])

    def test_test_patch_mixed_props_fail3(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.OK,
                     request_type=RequestType.PATCH_MIXED_PROPS,
                     json={'@odata.id': uri})
        req.test_patch_mixed_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_MIXED_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response did not include a message '
                      'annotation that lists the non-updatable properties',
                      result['msg'])

    def test_test_patch_mixed_props_pass(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.OK,
                     request_type=RequestType.PATCH_MIXED_PROPS,
                     json={'@odata.id': uri, '@Message.ExtendedInfo': [{}]})
        req.test_patch_mixed_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_MIXED_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_bad_prop_not_tested(self):
        req.test_patch_bad_prop(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_BAD_PROP, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH responses found for this condition; unable to '
                      'test this assertion', result['msg'])

    def test_test_patch_bad_prop_fail1(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.OK,
                     request_type=RequestType.PATCH_BAD_PROP)
        req.test_patch_bad_prop(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_BAD_PROP,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response returned status code %s; expected '
                      '%s' % (requests.codes.OK, requests.codes.BAD_REQUEST),
                      result['msg'])

    def test_test_patch_bad_prop_fail2(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_BAD_PROP,
                     json={'error': {'@Message.ExtendedInfo':
                           [{'Message': 'unknown property'}]}})
        req.test_patch_bad_prop(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_BAD_PROP,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response did not include a message that '
                      'lists the non-updatable property', result['msg'])

    def test_test_patch_bad_prop_pass(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_BAD_PROP,
                     json={'error': {'@Message.ExtendedInfo':
                           [{'Message': 'unknown property BogusProp'}]}})
        req.test_patch_bad_prop(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_BAD_PROP,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_ro_resource_not_tested(self):
        req.test_patch_ro_resource(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_RO_RESOURCE, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH responses found for this condition; unable to '
                      'test this assertion', result['msg'])

    def test_test_patch_ro_resource_fail(self):
        uri = '/redfish/v1/SessionService/Sessions/123'
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_RO_RESOURCE)
        req.test_patch_ro_resource(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_RO_RESOURCE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response returned status code %s; expected '
                      '%s' % (requests.codes.BAD_REQUEST,
                              requests.codes.METHOD_NOT_ALLOWED),
                      result['msg'])

    def test_test_patch_ro_resource_pass(self):
        uri = '/redfish/v1/SessionService/Sessions/123'
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.METHOD_NOT_ALLOWED,
                     request_type=RequestType.PATCH_RO_RESOURCE)
        req.test_patch_ro_resource(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_RO_RESOURCE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_patch_collection_not_tested(self):
        req.test_patch_collection(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_COLLECTION, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH responses found for this condition; unable to '
                      'test this assertion', result['msg'])

    def test_test_patch_patch_collection_fail(self):
        uri = '/redfish/v1/SessionService/Sessions'
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_COLLECTION)
        req.test_patch_collection(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_COLLECTION,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response returned status code %s; expected '
                      '%s' % (requests.codes.BAD_REQUEST,
                              requests.codes.METHOD_NOT_ALLOWED),
                      result['msg'])

    def test_test_patch_patch_collection_pass(self):
        uri = '/redfish/v1/SessionService/Sessions'
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.METHOD_NOT_ALLOWED,
                     request_type=RequestType.PATCH_COLLECTION)
        req.test_patch_collection(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_COLLECTION,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_patch_odata_props_not_tested(self):
        req.test_patch_odata_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ODATA_PROPS, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH responses found for this condition; unable to '
                      'test this assertion', result['msg'])

    def test_test_patch_patch_odata_props_fail1(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.METHOD_NOT_ALLOWED,
                     request_type=RequestType.PATCH_ODATA_PROPS)
        req.test_patch_odata_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ODATA_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        exp_codes = [requests.codes.OK, requests.codes.ACCEPTED,
                     requests.codes.NO_CONTENT, requests.codes.BAD_REQUEST]
        self.assertIn('The service response returned status code %s; expected '
                      'one of %s' % (requests.codes.METHOD_NOT_ALLOWED,
                                     exp_codes), result['msg'])

    def test_test_patch_patch_odata_props_fail2(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_ODATA_PROPS,
                     json={'error': {'@Message.ExtendedInfo': [{
                           'MessageId': 'Base.1.6.PropertyUnknown'}]}})
        req.test_patch_odata_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ODATA_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The service response did not include the NoOperation '
                      'message from the Base Message Registry', result['msg'])

    def test_test_patch_patch_odata_props_pass1(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.PATCH_ODATA_PROPS,
                     json={'error': {'@Message.ExtendedInfo': [{
                           'MessageId': 'Base.1.6.NoOperation'}]}})
        req.test_patch_odata_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ODATA_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_patch_odata_props_pass2(self):
        uri = self.account_uri
        add_response(self.sut, uri, method='PATCH',
                     status_code=requests.codes.OK,
                     request_type=RequestType.PATCH_ODATA_PROPS)
        req.test_patch_odata_props(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ODATA_PROPS,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_array_element_remove_fail1(self):
        uri = self.mgr_net_proto_uri
        response = add_response(self.sut, uri, 'PATCH',
                                status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.return_value = response
        req.test_patch_array_element_remove(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s; PATCH payload: ' %
                      requests.codes.BAD_REQUEST,
                      result['msg'])

    def test_test_patch_array_element_remove_fail2(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.side_effect = [r1, r2]
        req.test_patch_array_element_remove(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s; resource: ' %
                      requests.codes.BAD_REQUEST,
                      result['msg'])

    def test_test_patch_array_element_remove_fail3(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                ['time-a-b.nist.gov', 'time-b-b.nist.gov'],
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.NOT_FOUND)
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_element_remove(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Array element %s was not removed' %
                      'time-a-b.nist.gov', result['msg'])

    def test_test_patch_array_element_remove_not_tested(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': None,
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        req.test_patch_array_element_remove(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('After PATCH, NTPServers array not found in response',
                      result['msg'])

    def test_test_patch_array_element_remove_pass(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                ['time-b-b.nist.gov'],
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                ['time-b-b.nist.gov'],
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_element_remove(self.sut)
        result = get_result(self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_REMOVE,
                            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_array_element_unchanged_fail1(self):
        uri = self.mgr_net_proto_uri
        response = add_response(self.sut, uri, 'PATCH',
                                status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.return_value = response
        req.test_patch_array_element_unchanged(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s' %
                      requests.codes.BAD_REQUEST, result['msg'])

    def test_test_patch_array_element_unchanged_fail2(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.side_effect = [r1, r2]
        req.test_patch_array_element_unchanged(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s' %
                      requests.codes.BAD_REQUEST, result['msg'])

    def test_test_patch_array_element_unchanged_fail3(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                [{}, 'time-d-b.nist.gov'],
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.NOT_FOUND)
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_element_unchanged(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        missing = ['time-a-b.nist.gov']
        self.assertIn('left unchanged, but were not found in the response: %s'
                      % missing, result['msg'])

    def test_test_patch_array_element_unchanged_not_tested(self):
        uri = self.mgr_net_proto_uri
        response = add_response(self.sut, uri, 'PATCH',
                                status_code=requests.codes.OK,
                                json={'NTP': {'NTPServers': None,
                                      'ProtocolEnabled': False}})
        self.mock_session.patch.return_value = response
        req.test_patch_array_element_unchanged(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('After PATCH, NTPServers array not found in response',
                      result['msg'])

    def test_test_patch_array_element_unchanged_pass(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                ['time-a-b.nist.gov', 'time-d-b.nist.gov'],
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers':
                                ['time-a-b.nist.gov', 'time-d-b.nist.gov'],
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_element_unchanged(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_ELEMENT_UNCHANGED,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_array_truncate_fail1(self):
        uri = self.mgr_net_proto_uri
        response = add_response(self.sut, uri, 'PATCH',
                                status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.return_value = response
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s' %
                      requests.codes.BAD_REQUEST, result['msg'])

    def test_test_patch_array_truncate_fail2(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.side_effect = [r1, r2]
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH failed with status %s' %
                      requests.codes.BAD_REQUEST, result['msg'])

    def test_test_patch_array_truncate_fail3(self):
        uri = self.mgr_net_proto_uri
        expected_array = ['time-b-b.nist.gov']
        array = ['time-b-b.nist.gov', 'time-c-b.nist.gov']
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': array,
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.NOT_FOUND)
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('expected NTPServers array to be %s; found: %s' %
                      (expected_array, array), result['msg'])

    def test_test_patch_array_truncate_not_tested(self):
        uri = self.mgr_net_proto_uri
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': None,
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('After PATCH, NTPServers array not found in response',
                      result['msg'])

    def test_test_patch_array_truncate_pass(self):
        uri = self.mgr_net_proto_uri
        array = ['time-b-b.nist.gov']
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': array,
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': array,
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_patch_array_truncate_pass2(self):
        uri = self.mgr_net_proto_uri
        array = ['time-b-b.nist.gov', None]
        r1 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK)
        r2 = add_response(self.sut, uri, 'PATCH',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': array,
                                'ProtocolEnabled': False}})
        r3 = add_response(self.sut, uri, 'GET',
                          status_code=requests.codes.OK,
                          json={'NTP': {'NTPServers': array,
                                'ProtocolEnabled': False}})
        self.mock_session.patch.side_effect = [r1, r2]
        self.mock_session.get.return_value = r3
        req.test_patch_array_truncate(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_PATCH_ARRAY_TRUNCATE,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    @mock.patch('redfish_protocol_validator.service_requests.logging.warning')
    def test_patch_array_restore_warning(self, mock_warning):
        uri = self.mgr_net_proto_uri
        response = add_response(self.sut, uri, 'PATCH',
                                status_code=requests.codes.BAD_REQUEST)
        self.mock_session.patch.return_value = response
        req.patch_array_restore(self.sut, ['', '', ''])
        self.assertEqual(mock_warning.call_count, 1)
        args = mock_warning.call_args[0]
        self.assertIn('failed with status %s' % requests.codes.BAD_REQUEST,
                      args[0])

    def test_test_post_create_via_collection_not_tested(self):
        uri = self.sut.sessions_uri
        req.test_post_create_via_collection(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_VIA_COLLECTION,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Not response found for POST to Sessions URI',
                      result['msg'])

    def test_test_post_create_via_collection_fail(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.METHOD_NOT_ALLOWED)
        req.test_post_create_via_collection(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_VIA_COLLECTION,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('POST request to collections uri %s failed with status '
                      '%s' % (uri, requests.codes.METHOD_NOT_ALLOWED),
                      result['msg'])

    def test_test_post_create_via_collection_pass(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.CREATED)
        req.test_post_create_via_collection(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_VIA_COLLECTION,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_post_create_uri_in_location_hdr_not_tested(self):
        uri = self.sut.sessions_uri
        req.test_post_create_uri_in_location_hdr(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No successful response found for POST to Sessions URI',
                      result['msg'])

    def test_test_post_create_uri_in_location_hdr_fail(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.CREATED)
        req.test_post_create_uri_in_location_hdr(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Location header missing from response to POST request',
                      result['msg'])

    def test_test_post_create_uri_in_location_hdr_pass(self):
        uri = self.sut.sessions_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.CREATED,
                     headers={'Location':
                              '/redfish/v1/SessionService/Sessions/123'})
        req.test_post_create_uri_in_location_hdr(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_URI_IN_LOCATION_HDR,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_to_members_prop_fail(self, mock_post):
        uri = self.sut.sessions_uri + '/Members'
        response = add_response(self.sut, uri, 'POST',
                                status_code=requests.codes.NOT_FOUND)
        mock_post.return_value = response
        req.test_post_create_to_members_prop(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_TO_MEMBERS_PROP,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('POST to Members property URI %s failed with status %s'
                      % (uri, requests.codes.NOT_FOUND), result['msg'])

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_to_members_prop_pass(self, mock_post):
        uri = self.sut.sessions_uri + '/Members'
        session_uri = '/redfish/v1/SessionService/Sessions/123'
        response = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri})
        mock_post.return_value = response
        req.test_post_create_to_members_prop(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_TO_MEMBERS_PROP,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.mock_session.delete.assert_called_with(
            self.sut.rhost + session_uri)

    def test_test_post_create_not_supported_not_tested(self):
        uri = self.sut.accounts_uri
        req.test_post_create_not_supported(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found for POST to Accounts URI',
                      result['msg'])

    def test_test_post_create_not_supported_fail(self):
        uri = self.sut.accounts_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.BAD_REQUEST)
        req.test_post_create_not_supported(self.sut)
        result = get_result(self.sut, Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('POST request to URI %s failed with %s; expected %s' %
                      (uri, requests.codes.BAD_REQUEST,
                       requests.codes.METHOD_NOT_ALLOWED), result['msg'])

    def test_test_post_create_not_supported_pass1(self):
        uri = self.sut.accounts_uri
        add_response(self.sut, uri, 'POST', status_code=requests.codes.CREATED)
        req.test_post_create_not_supported(self.sut)
        result = get_result(self.sut, Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Service supports creation of resources', result['msg'])

    def test_test_post_create_not_supported_pass2(self):
        uri = self.sut.accounts_uri
        add_response(self.sut, uri, 'POST',
                     status_code=requests.codes.METHOD_NOT_ALLOWED)
        req.test_post_create_not_supported(self.sut)
        result = get_result(self.sut, Assertion.REQ_POST_CREATE_NOT_SUPPORTED,
                            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertIn('Test passed', result['msg'])

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_not_idempotent_not_tested1(self, mock_post):
        uri = self.sut.sessions_uri
        response = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.BAD_REQUEST)
        mock_post.return_value = response
        req.test_post_create_not_idempotent(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('POST request to %s failed with status code %s' %
                      (uri, requests.codes.BAD_REQUEST), result['msg'])

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_not_idempotent_warn(self, mock_post):
        uri = self.sut.sessions_uri
        session_uri = '/redfish/v1/Sessions/123'
        r1 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri})
        r2 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.BAD_REQUEST)
        mock_post.side_effect = [r1, r2]
        req.test_post_create_not_idempotent(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('Second POST request to %s failed with status code %s' %
                      (uri, requests.codes.BAD_REQUEST), result['msg'])
        self.mock_session.delete.assert_called_with(
            self.sut.rhost + session_uri)
        self.assertEqual(self.mock_session.delete.call_count, 1)

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_not_idempotent_not_tested2(self, mock_post):
        uri = self.sut.sessions_uri
        session_uri = '/redfish/v1/Sessions/123'
        r1 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri})
        r2 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={})
        mock_post.side_effect = [r1, r2]
        req.test_post_create_not_idempotent(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('POST request to %s did not return a Location header' %
                      uri, result['msg'])
        self.mock_session.delete.assert_called_with(
            self.sut.rhost + session_uri)
        self.assertEqual(self.mock_session.delete.call_count, 1)

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_not_idempotent_fail(self, mock_post):
        uri = self.sut.sessions_uri
        session_uri = '/redfish/v1/Sessions/123'
        r1 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri})
        r2 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri})
        mock_post.side_effect = [r1, r2]
        req.test_post_create_not_idempotent(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('the same resource URI in the Location header (%s)' %
                      session_uri, result['msg'])
        self.mock_session.delete.assert_called_with(
            self.sut.rhost + session_uri)
        self.assertEqual(self.mock_session.delete.call_count, 1)

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_post_create_not_idempotent_pass(self, mock_post):
        uri = self.sut.sessions_uri
        session_uri1 = '/redfish/v1/Sessions/123'
        session_uri2 = '/redfish/v1/Sessions/456'
        r1 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri1})
        r2 = add_response(
            self.sut, uri, 'POST', status_code=requests.codes.CREATED,
            headers={'Location': session_uri2})
        mock_post.side_effect = [r1, r2]
        req.test_post_create_not_idempotent(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_POST_CREATE_NOT_IDEMPOTENT,
            'POST', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.mock_session.delete.assert_called_with(
            self.sut.rhost + session_uri1)
        self.assertEqual(self.mock_session.delete.call_count, 2)

    def test_test_delete_method_required_not_tested(self):
        req.test_delete_method_required(self.sut)
        result = get_result(self.sut, Assertion.REQ_DELETE_METHOD_REQUIRED,
                            'DELETE', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No DELETE responses found', result['msg'])

    def test_test_delete_method_required_fail(self):
        uri = '/redfish/v1/SessionService/Sessions/123'
        add_response(self.sut, uri, 'DELETE',
                     status_code=requests.codes.METHOD_NOT_ALLOWED)
        req.test_delete_method_required(self.sut)
        result = get_result(self.sut, Assertion.REQ_DELETE_METHOD_REQUIRED,
                            'DELETE', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertEqual(uri, result['uri'])
        self.assertEqual(requests.codes.METHOD_NOT_ALLOWED, result['status'])
        self.assertIn('No successful DELETE responses found', result['msg'])

    def test_test_delete_method_required_pass(self):
        uri1 = '/redfish/v1/SessionService/Sessions/123'
        uri2 = '/redfish/v1/SessionService/Sessions/456'
        add_response(self.sut, uri1, 'DELETE',
                     status_code=requests.codes.METHOD_NOT_ALLOWED)
        add_response(self.sut, uri2, 'DELETE',
                     status_code=requests.codes.OK)
        req.test_delete_method_required(self.sut)
        result = get_result(self.sut, Assertion.REQ_DELETE_METHOD_REQUIRED,
                            'DELETE', uri2)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertEqual(uri2, result['uri'])
        self.assertEqual(requests.codes.OK, result['status'])

    def test_test_delete_non_deletable_resource_not_tested(self):
        req.test_delete_non_deletable_resource(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE,
            'DELETE', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No failed DELETE responses found', result['msg'])

    def test_test_delete_non_deletable_resource_warn(self):
        uri = '/redfish/v1/SessionService/Sessions/123'
        add_response(self.sut, uri, 'DELETE',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.UNSUPPORTED_REQ)
        req.test_delete_non_deletable_resource(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE,
            'DELETE', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('DELETE request for resource %s failed with status %s'
                      % (uri, requests.codes.BAD_REQUEST), result['msg'])
        self.assertEqual(uri, result['uri'])
        self.assertEqual(requests.codes.BAD_REQUEST, result['status'])

    def test_test_delete_non_deletable_resource_pass(self):
        uri1 = '/redfish/v1/SessionService/Sessions/123'
        uri2 = '/redfish/v1/SessionService/Sessions/456'
        add_response(self.sut, uri1, 'DELETE',
                     status_code=requests.codes.BAD_REQUEST,
                     request_type=RequestType.UNSUPPORTED_REQ)
        add_response(self.sut, uri2, 'DELETE',
                     status_code=requests.codes.METHOD_NOT_ALLOWED,
                     request_type=RequestType.UNSUPPORTED_REQ)
        req.test_delete_non_deletable_resource(self.sut)
        result = get_result(
            self.sut, Assertion.REQ_DELETE_NON_DELETABLE_RESOURCE,
            'DELETE', uri2)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertEqual(uri2, result['uri'])
        self.assertEqual(requests.codes.METHOD_NOT_ALLOWED, result['status'])

    @mock.patch('redfish_protocol_validator.service_requests.requests.post')
    def test_test_service_requests_cover(self, mock_post):
        req.test_service_requests(self.sut)


if __name__ == '__main__':
    unittest.main()
