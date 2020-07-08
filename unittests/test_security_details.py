# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests
from requests.exceptions import SSLError

from assertions import security_details as sec
from assertions.constants import Assertion, Result, RequestType, ResourceType
from assertions.system_under_test import SystemUnderTest
from unittests.utils import add_response, get_result


class SecurityDetails(TestCase):

    def setUp(self):
        super(SecurityDetails, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.account_uri = '/redfish/v1/AccountsService/Accounts/3/'
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)
        patch_post = mock.patch('assertions.security_details.requests.post')
        self.mock_post = patch_post.start()
        self.addCleanup(patch_post.stop)
        patch_get = mock.patch('assertions.security_details.requests.get')
        self.mock_get = patch_get.start()
        self.addCleanup(patch_get.stop)
        patch_ssl_ctx = mock.patch(
            'assertions.security_details.ssl.SSLContext')
        self.mock_ssl_ctx = patch_ssl_ctx.start()
        self.addCleanup(patch_ssl_ctx.stop)
        patch_ssl_sock = mock.patch(
            'assertions.security_details.ssl.SSLSocket')
        self.mock_ssl_sock = patch_ssl_sock.start()
        self.addCleanup(patch_ssl_sock.stop)
        patch_decoder = mock.patch('assertions.security_details.decoder')
        self.mock_decoder = patch_decoder.start()
        self.addCleanup(patch_decoder.stop)
        add_response(self.sut, self.sut.sessions_uri, 'GET', requests.codes.OK)
        add_response(self.sut, self.sut.sessions_uri, 'GET', requests.codes.OK,
                     request_type=RequestType.BASIC_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED)
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED,
                     request_type=RequestType.HTTP_BASIC_AUTH)
        add_response(self.sut, self.account_uri,
                     'PATCH', requests.codes.NOT_ALLOWED,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, '/redfish/v1/', 'GET', requests.codes.OK,
                     json={'SessionService': {'@odata.id': '/redfish/v1/ss'},
                           'Links': {'Sessions':
                                     {'@odata.id': '/redfish/v1/sessions'}}})
        add_response(self.sut, '/redfish/v1/ss', 'GET', requests.codes.OK,
                     json={'Sessions': {'@odata.id': '/redfish/v1/sessions'}})
        add_response(self.sut, '/redfish/v1/',
                     'GET', requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, '/redfish/v1/x/y', 'POST',
                     requests.codes.BAD_REQUEST,
                     text='...bad password...',
                     request_type=RequestType.BAD_AUTH)
        add_response(self.sut, self.account_uri,
                     'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT)

    @mock.patch('assertions.security_details.requests.Session')
    def test_test_tls_1_1_pass(self, mock_session):
        mock_session.return_value.mount.return_value = None
        sec.test_tls_1_1(self.sut)
        result = get_result(self.sut, Assertion.SEC_TLS_1_1, 'GET',
                            '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    @mock.patch('assertions.security_details.requests.Session')
    def test_test_tls_1_1_fail(self, mock_session):
        mock_session.return_value.mount.return_value = None
        mock_session.return_value.get.side_effect = SSLError
        sec.test_tls_1_1(self.sut)
        result = get_result(self.sut, Assertion.SEC_TLS_1_1, 'GET',
                            '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Unable to connect to', result['msg'])

    def test_test_basic_auth_standalone_pass(self):
        sec.test_basic_auth_standalone(self.sut)
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_STANDALONE,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_basic_auth_standalone_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.BASIC_AUTH)
        sec.test_basic_auth_standalone(self.sut)
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_STANDALONE,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status code 401', result['msg'])

    def test_test_basic_auth_standalone_not_tested(self):
        self.sut.set_sessions_uri('redfish/v1/foo/bar')
        sec.test_basic_auth_standalone(self.sut)
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_STANDALONE,
                            'GET', 'redfish/v1/foo/bar')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found for', result['msg'])

    def test_test_both_auth_types_pass(self):
        sec.test_both_auth_types(self.sut)
        result = get_result(self.sut, Assertion.SEC_BOTH_AUTH_TYPES,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_both_auth_types_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.BASIC_AUTH)
        sec.test_both_auth_types(self.sut)
        result = get_result(self.sut, Assertion.SEC_BOTH_AUTH_TYPES,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status code 401', result['msg'])

    def test_test_both_auth_types_not_tested(self):
        self.sut.set_sessions_uri('redfish/v1/foo/bar')
        sec.test_both_auth_types(self.sut)
        result = get_result(self.sut, Assertion.SEC_BOTH_AUTH_TYPES,
                            'GET', 'redfish/v1/foo/bar')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found for', result['msg'])

    def test_test_write_requires_auth_pass(self):
        sec.test_write_requires_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_WRITE_REQUIRES_AUTH,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_write_requires_auth_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.NOT_ALLOWED,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, self.account_uri, 'PATCH',
                     requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        sec.test_write_requires_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_WRITE_REQUIRES_AUTH,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('with no authentication failed with status 405',
                      result['msg'])
        result = get_result(self.sut, Assertion.SEC_WRITE_REQUIRES_AUTH,
                            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('with no authentication succeeded with status 200',
                      result['msg'])

    def test_test_read_requires_auth_pass(self):
        sec.test_read_requires_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_READ_REQUIRES_AUTH,
                            'GET', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(self.sut, Assertion.SEC_READ_REQUIRES_AUTH,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_read_requires_auth_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, '/redfish/v1/odata',
                     'GET', requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        sec.test_read_requires_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_READ_REQUIRES_AUTH,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('with no authentication succeeded with status 200',
                      result['msg'])
        result = get_result(self.sut, Assertion.SEC_READ_REQUIRES_AUTH,
                            'GET', '/redfish/v1/odata')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('with no authentication failed with status 401',
                      result['msg'])

    def test_test_headers_auth_before_etag_pass(self):
        self.mock_get.return_value.status_code = requests.codes.UNAUTHORIZED
        sec.test_headers_auth_before_etag(self.sut)
        result = get_result(self.sut, Assertion.SEC_HEADERS_FIRST,
                            'GET', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_headers_auth_before_etag_fail(self):
        self.mock_get.return_value.status_code = requests.codes.NOT_MODIFIED
        sec.test_headers_auth_before_etag(self.sut)
        result = get_result(self.sut, Assertion.SEC_HEADERS_FIRST,
                            'GET', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status 304; expected status 401',
                      result['msg'])

    def test_test_headers_auth_before_etag_not_tested1(self):
        sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        sec.test_headers_auth_before_etag(sut)
        result = get_result(sut, Assertion.SEC_HEADERS_FIRST, 'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ManagerAccount GET responses found', result['msg'])

    def test_test_headers_auth_before_etag_not_tested2(self):
        self.mock_get.return_value.status_code = requests.codes.BAD_REQUEST
        sec.test_headers_auth_before_etag(self.sut)
        result = get_result(self.sut, Assertion.SEC_HEADERS_FIRST, 'GET',
                            self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('bad authentication returned unexpected status 400',
                      result['msg'])

    def test_test_no_auth_cookies_pass(self):
        sec.test_no_auth_cookies(self.sut)
        result = get_result(self.sut, Assertion.SEC_NO_AUTH_COOKIES,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_no_auth_cookies_warn(self):
        headers = {'Set-Cookie': 'MyCookie=SomeValue'}
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED, headers=headers)
        sec.test_no_auth_cookies(self.sut)
        result = get_result(self.sut, Assertion.SEC_NO_AUTH_COOKIES,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('Set-Cookie header found in', result['msg'])

    def test_test_no_auth_cookies_not_tested(self):
        self.sut.set_sessions_uri('redfish/v1/foo/bar')
        sec.test_no_auth_cookies(self.sut)
        result = get_result(self.sut, Assertion.SEC_NO_AUTH_COOKIES,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('unable to test this assertion', result['msg'])

    def test_test_support_basic_auth_pass(self):
        sec.test_support_basic_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_SUPPORT_BASIC_AUTH,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_support_basic_auth_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.BASIC_AUTH)
        sec.test_support_basic_auth(self.sut)
        result = get_result(self.sut, Assertion.SEC_SUPPORT_BASIC_AUTH,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('basic auth failed with status 401', result['msg'])

    def test_test_require_login_sessions_pass(self):
        response = self.sut.get_response('POST', self.sut.sessions_uri)
        response.headers = {'Location': '/redfish/v1/foo/bar',
                            'X-Auth-Token': 'abcdef40'}
        sec.test_require_login_sessions(self.sut)
        result = get_result(self.sut, Assertion.SEC_REQUIRE_LOGIN_SESSIONS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_require_login_sessions_fail(self):
        response = self.sut.get_response('POST', self.sut.sessions_uri)
        # only Location header received
        response.headers = {'Location': '/redfish/v1/foo/bar'}
        sec.test_require_login_sessions(self.sut)
        result = get_result(self.sut, Assertion.SEC_REQUIRE_LOGIN_SESSIONS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('X-Auth-Token header was not returned', result['msg'])
        # only X-Auth-Token header received
        response.headers = {'X-Auth-Token': 'abcdef40'}
        sec.test_require_login_sessions(self.sut)
        result = get_result(self.sut, Assertion.SEC_REQUIRE_LOGIN_SESSIONS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Location header was not returned', result['msg'])
        # Neither header received
        response.headers = {}
        sec.test_require_login_sessions(self.sut)
        result = get_result(self.sut, Assertion.SEC_REQUIRE_LOGIN_SESSIONS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Location and X-Auth-Token headers were not returned',
                      result['msg'])
        # request failed
        response.status_code = requests.codes.bad_request
        response.ok = False
        sec.test_require_login_sessions(self.sut)
        result = get_result(self.sut, Assertion.SEC_REQUIRE_LOGIN_SESSIONS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('create a login session failed with status 400',
                      result['msg'])

    def test_test_certs_conform_to_x509v3_pass(self):
        # duck typing the decode result; it's not really array of dict()
        self.mock_decoder.decode.return_value = [
            {
                'tbsCertificate': {
                    'version': 'v3'
                }
            }
        ]
        sec.test_certs_conform_to_x509v3(self.sut)
        result = get_result(self.sut, Assertion.SEC_CERTS_CONFORM_X509V3,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_certs_conform_to_x509v3_fail(self):
        # duck typing the decode result; it's not really array of dict()
        self.mock_decoder.decode.return_value = [
            {
                'tbsCertificate': {
                    'version': 'v2'
                }
            }
        ]
        sec.test_certs_conform_to_x509v3(self.sut)
        result = get_result(self.sut, Assertion.SEC_CERTS_CONFORM_X509V3,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('the version retrieved is v2', result['msg'])

    def test_test_certs_conform_to_x509v3_not_tested(self):
        sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sec.test_certs_conform_to_x509v3(sut)
        result = get_result(sut, Assertion.SEC_CERTS_CONFORM_X509V3,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('is not HTTPS', result['msg'])

    def test_test_certs_conform_to_x509v3_except(self):
        self.mock_decoder.decode.side_effect = Exception('decoding error')
        sec.test_certs_conform_to_x509v3(self.sut)
        result = get_result(self.sut, Assertion.SEC_CERTS_CONFORM_X509V3,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('decoding error', result['msg'])

    def test_test_redirect_enforces_target_privs_pass(self):
        response = add_response(self.sut, self.sut.sessions_uri, 'GET',
                                requests.codes.UNAUTHORIZED,
                                request_type=RequestType.HTTP_NO_AUTH)
        redirect = mock.MagicMock(spec=requests.Response)
        response.history = [redirect]
        sec.test_redirect_enforces_target_privs(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_redirect_enforces_target_privs_fail(self):
        response = add_response(self.sut, self.sut.sessions_uri, 'GET',
                                requests.codes.OK,
                                request_type=RequestType.HTTP_NO_AUTH)
        redirect = mock.MagicMock(spec=requests.Response)
        redirect.url = 'http://127.0.0.1/redfish/v1/SessionService/Sessions'
        response.history = [redirect]
        sec.test_redirect_enforces_target_privs(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('was 200, expected 401', result['msg'])

    def test_test_redirect_enforces_target_privs_not_tested(self):
        sec.test_redirect_enforces_target_privs(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found with an HTTP redirect', result['msg'])

    def test_test_redirect_to_https_pass(self):
        response = add_response(self.sut, '/redfish/v1/', 'GET',
                                requests.codes.OK,
                                request_type=RequestType.HTTP_NO_AUTH)
        redirect = mock.MagicMock(spec=requests.Response)
        response.history = [redirect]
        sec.test_redirect_to_https(self.sut)
        result = get_result(self.sut, Assertion.SEC_REDIRECT_TO_HTTPS,
                            'GET', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_redirect_to_https_fail(self):
        response = add_response(self.sut, '/redfish/v1/', 'GET',
                                requests.codes.NOT_FOUND,
                                request_type=RequestType.HTTP_NO_AUTH)
        redirect = mock.MagicMock(spec=requests.Response)
        redirect.url = 'http://127.0.0.1/redfish/v1/'
        response.history = [redirect]
        sec.test_redirect_to_https(self.sut)
        result = get_result(self.sut, Assertion.SEC_REDIRECT_TO_HTTPS,
                            'GET', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('was 404, expected 200', result['msg'])

    def test_test_redirect_to_https_not_tested(self):
        sec.test_redirect_to_https(self.sut)
        result = get_result(self.sut, Assertion.SEC_REDIRECT_TO_HTTPS,
                            'GET', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found with an HTTP redirect', result['msg'])

    def test_test_no_priv_info_in_msgs_pass(self):
        sec.test_no_priv_info_in_msgs(self.sut)
        result = get_result(self.sut, Assertion.SEC_NO_PRIV_INFO_IN_MSGS,
                            'POST', '/redfish/v1/x/y')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_no_priv_info_in_msgs_fail(self):
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.BAD_REQUEST,
                     text='...bad password %s...' % self.sut.password,
                     request_type=RequestType.BAD_AUTH)
        sec.test_no_priv_info_in_msgs(self.sut)
        result = get_result(self.sut, Assertion.SEC_NO_PRIV_INFO_IN_MSGS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('may have provided privileged information ("*****")',
                      result['msg'])

    def test_test_basic_auth_over_https_pass(self):
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.FORBIDDEN,
                     request_type=RequestType.HTTP_BASIC_AUTH)
        sec.test_basic_auth_over_https(self.sut)
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_OVER_HTTPS,
                            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_OVER_HTTPS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_basic_auth_over_https_fail(self):
        response = self.sut.get_response(
            'POST', self.sut.sessions_uri,
            request_type=RequestType.HTTP_BASIC_AUTH)
        response.url = 'http://127.0.0.1:8000/redfish/v1/Sessions/'
        sec.test_basic_auth_over_https(self.sut)
        result = get_result(self.sut, Assertion.SEC_BASIC_AUTH_OVER_HTTPS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('but did not redirect to HTTPS', result['msg'])

    def test_test_sessions_uri_location_pass(self):
        sec.test_sessions_uri_location(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSIONS_URI_LOCATION,
                            'GET', '/redfish/v1/sessions')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sessions_uri_location_fail1(self):
        add_response(self.sut, '/redfish/v1/', 'GET', requests.codes.OK,
                     json={'SessionService': {'@odata.id': '/redfish/v1/ss'},
                           'Links': {'Sezzions':
                                     {'@odata.id': '/redfish/v1/sessions'}}})
        sec.test_sessions_uri_location(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSIONS_URI_LOCATION,
                            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('URI from ServiceRoot Links property not found',
                      result['msg'])

    def test_test_sessions_uri_location_fail2(self):
        add_response(self.sut, '/redfish/v1/ss', 'GET', requests.codes.OK,
                     json={'Sessions': {'@odata.id': '/redfish/v1/sezzions'}})
        sec.test_sessions_uri_location(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSIONS_URI_LOCATION,
                            'GET', '/redfish/v1/sessions')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('not equal to URI from SessionService',
                      result['msg'])

    def test_test_sessions_uri_location_not_tested(self):
        add_response(self.sut, '/redfish/v1/ss', 'GET', requests.codes.OK,
                     json={'Sezzions': {'@odata.id': '/redfish/v1/sessions'}})
        sec.test_sessions_uri_location(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSIONS_URI_LOCATION,
                            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('URI from SessionService resource not found',
                      result['msg'])

    def test_test_session_post_response_pass(self):
        response_payload = {
            '@odata.id': '/redfish/v1/SessionService/Sessions/1',
            '@odata.type': '#Session.v1_0_0.Session',
            'Id': '1',
            'Name': 'User Session',
            'UserName': 'some_user',
            'Password': None
        }
        headers = {'X-Auth-Token': 'abcdef40',
                   'Location': '/redfish/v1/SessionService/Sessions/1'}
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED, json=response_payload,
                     headers=headers)
        sec.test_session_post_response(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSION_POST_RESPONSE,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_session_post_response_fail(self):
        sec.test_session_post_response(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSION_POST_RESPONSE,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('did not contain full representation of the new session',
                      result['msg'])

    def test_test_session_post_response_not_tested(self):
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.BAD_REQUEST)
        sec.test_session_post_response(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSION_POST_RESPONSE,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('was not successful; cannot test this assertion',
                      result['msg'])

    def test_test_session_create_https_only_pass1(self):
        sec.test_session_create_https_only(self.sut)
        result = get_result(self.sut, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_session_create_https_only_pass2(self):
        sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        add_response(sut, sut.sessions_uri, 'POST',
                     requests.codes.NOT_FOUND)
        sec.test_session_create_https_only(sut)
        result = get_result(sut, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                            'POST', sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_session_create_https_only_fail(self):
        sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        add_response(sut, sut.sessions_uri, 'POST',
                     requests.codes.CREATED)
        sec.test_session_create_https_only(sut)
        result = get_result(sut, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                            'POST', sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('should fail or redirect to HTTPS',
                      result['msg'])

    def test_test_session_create_https_only_not_tested(self):
        sut = SystemUnderTest('ftp://127.0.0.1:8000', 'oper', 'xyzzy')
        sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        sec.test_session_create_https_only(sut)
        result = get_result(sut, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                            'POST', sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Unexpected scheme (ftp)',
                      result['msg'])

    def test_test_session_termination_side_effects_not_tested1(self):
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEventUri available', result['msg'])

    @mock.patch('assertions.sessions.requests.post')
    def test_test_session_termination_side_effects_not_tested2(
            self, mock_post):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        post_req = mock.Mock(spec=requests.Request)
        post_req.method = 'POST'
        post_resp = mock.Mock(spec=requests.Response)
        post_resp.status_code = requests.codes.BAD_REQUEST
        post_resp.ok = False
        post_resp.request = post_req
        mock_post.return_value = post_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Failed to create session', result['msg'])

    @mock.patch('assertions.sessions.create_session')
    @mock.patch('assertions.security_details.requests.Session')
    def test_test_session_termination_side_effects_not_tested3(
            self, mock_session, mock_create_session):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        sess_uri = '/redfish/v1/SessionService/Sessions/9'
        token = '87a5cd20'
        mock_create_session.return_value = sess_uri, token
        get_resp = mock.Mock(spec=requests.Response)
        get_resp.status_code = requests.codes.NOT_FOUND
        get_resp.ok = False
        mock_session.return_value.headers = {}
        mock_session.return_value.get.return_value = get_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'GET', self.sut.server_sent_event_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Opening ServerSentEventUri %s failed' %
                      self.sut.server_sent_event_uri, result['msg'])

    @mock.patch('assertions.sessions.create_session')
    @mock.patch('assertions.security_details.requests.Session')
    def test_test_session_termination_side_effects_not_tested4(
            self, mock_session, mock_create_session):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        sess_uri = '/redfish/v1/SessionService/Sessions/9'
        token = '87a5cd20'
        mock_create_session.return_value = sess_uri, token
        get_resp = mock.Mock(spec=requests.Response)
        get_resp.status_code = requests.codes.OK
        get_resp.ok = True
        del_resp = mock.Mock(spec=requests.Response)
        del_resp.status_code = requests.codes.UNAUTHORIZED
        del_resp.ok = False
        mock_session.return_value.headers = {}
        mock_session.return_value.get.return_value = get_resp
        mock_session.return_value.delete.return_value = del_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'DELETE', sess_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Deleting session %s failed' % sess_uri, result['msg'])

    @mock.patch('assertions.sessions.create_session')
    @mock.patch('assertions.security_details.requests.Session')
    def test_test_session_termination_side_effects_fail1(
            self, mock_session, mock_create_session):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        sess_uri = '/redfish/v1/SessionService/Sessions/9'
        token = '87a5cd20'
        mock_create_session.return_value = sess_uri, token
        get_resp = mock.Mock(spec=requests.Response)
        get_resp.status_code = requests.codes.OK
        get_resp.ok = True
        get_resp.iter_lines.side_effect = ConnectionError('connection closed')
        del_resp = mock.Mock(spec=requests.Response)
        del_resp.status_code = requests.codes.OK
        del_resp.ok = True
        mock_session.return_value.headers = {}
        mock_session.return_value.get.return_value = get_resp
        mock_session.return_value.delete.return_value = del_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'GET', self.sut.server_sent_event_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Exception raised while trying to read from '
                      'ServerSentEventUri stream %s after' %
                      self.sut.server_sent_event_uri, result['msg'])

    @mock.patch('assertions.sessions.create_session')
    @mock.patch('assertions.security_details.requests.Session')
    def test_test_session_termination_side_effects_fail2(
            self, mock_session, mock_create_session):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        sess_uri = '/redfish/v1/SessionService/Sessions/9'
        token = '87a5cd20'
        mock_create_session.return_value = sess_uri, token
        get_resp = mock.Mock(spec=requests.Response)
        get_resp.status_code = requests.codes.OK
        get_resp.ok = True
        get_resp.iter_lines.return_value = []
        del_resp = mock.Mock(spec=requests.Response)
        del_resp.status_code = requests.codes.OK
        del_resp.ok = True
        mock_session.return_value.headers = {}
        mock_session.return_value.get.return_value = get_resp
        mock_session.return_value.delete.return_value = del_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'GET', self.sut.server_sent_event_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Unable to read from ServerSentEventUri stream %s after'
                      % self.sut.server_sent_event_uri, result['msg'])

    @mock.patch('assertions.sessions.create_session')
    @mock.patch('assertions.security_details.requests.Session')
    def test_test_session_termination_side_effects_pass(
            self, mock_session, mock_create_session):
        self.sut.set_server_sent_event_uri('/redfish/v1/EventService/SSE')
        sess_uri = '/redfish/v1/SessionService/Sessions/9'
        token = '87a5cd20'
        mock_create_session.return_value = sess_uri, token
        get_resp = mock.Mock(spec=requests.Response)
        get_resp.status_code = requests.codes.OK
        get_resp.ok = True
        get_resp.iter_lines.return_value = [': stream keep-alive', '']
        del_resp = mock.Mock(spec=requests.Response)
        del_resp.status_code = requests.codes.OK
        del_resp.ok = True
        mock_session.return_value.headers = {}
        mock_session.return_value.get.return_value = get_resp
        mock_session.return_value.delete.return_value = del_resp
        sec.test_session_termination_side_effects(self.sut)
        result = get_result(self.sut,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            'GET', self.sut.server_sent_event_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_accounts_support_etags_pass(self):
        add_response(self.sut, self.account_uri, 'PATCH',
                     requests.codes.precondition_failed,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.BAD_ETAG)
        sec.test_accounts_support_etags(self.sut)
        result = get_result(self.sut, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS,
                            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_accounts_support_etags_not_tested(self):
        sec.test_accounts_support_etags(self.sut)
        result = get_result(self.sut, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS,
                            'PATCH', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH request to account resource with stale',
                      result['msg'])

    def test_test_accounts_support_etags_warn(self):
        add_response(self.sut, self.account_uri, 'PATCH',
                     requests.codes.bad_request,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.BAD_ETAG)
        sec.test_accounts_support_etags(self.sut)
        result = get_result(self.sut, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS,
                            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('failed with status %s; expected it to fail with status '
                      '%s' % (requests.codes.bad_request,
                              requests.codes.precondition_failed),
                      result['msg'])

    def test_test_accounts_support_etags_fail(self):
        add_response(self.sut, self.account_uri, 'PATCH',
                     requests.codes.ok,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.BAD_ETAG)
        sec.test_accounts_support_etags(self.sut)
        result = get_result(self.sut, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS,
                            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('URI %s with stale If-Match header succeeded' %
                      self.account_uri, result['msg'])

    def test_test_password_change_required_pass(self):
        ext_info = {
            'error': {
                '@Message.ExtendedInfo': [
                    {
                        'MessageId': 'Base.1.0.PasswordChangeRequired'
                    }
                ]
            }
        }
        acct_payload = {
            'PasswordChangeRequired': False
        }
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=ext_info)
        add_response(self.sut, self.account_uri,
                     'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.FORBIDDEN,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=ext_info)
        add_response(self.sut, self.account_uri,
                     'PATCH', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=acct_payload)
        sec.test_password_change_required(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN,
            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT,
            'GET', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS,
            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_password_change_required_fail1(self):
        ext_info = {
            'error': {
                '@Message.ExtendedInfo': [
                    {
                        'MessageId': 'Base.1.0.Success'
                    }
                ]
            }
        }
        acct_payload = {
            'PasswordChangeRequired': True
        }
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=ext_info)
        add_response(self.sut, self.account_uri,
                     'GET', requests.codes.FORBIDDEN,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.FORBIDDEN,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=ext_info)
        add_response(self.sut, self.account_uri,
                     'PATCH', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED,
                     json=acct_payload)
        sec.test_password_change_required(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN,
            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('did not contain PasswordChangeRequired message',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT,
            'GET', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PasswordChangeRequired set failed with status 403',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS,
            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('did not contain PasswordChangeRequired message',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('not have PasswordChangeRequired property set to false',
                      result['msg'])

    def test_test_password_change_required_fail2(self):
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.FORBIDDEN,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        add_response(self.sut, self.account_uri,
                     'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.OK,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        add_response(self.sut, self.account_uri,
                     'PATCH', requests.codes.FORBIDDEN,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        sec.test_password_change_required(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN,
            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PasswordChangeRequired set failed with status 403',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS,
            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('with status 200; expected it to fail with status 403',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Password change to %s failed with status 403'
                      % self.account_uri, result['msg'])

    def test_test_password_change_required_not_tested1(self):
        sec.test_password_change_required(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN,
            'POST', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('PasswordChangeRequired property not found in account',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT,
            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No GET request to account URI found',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS,
            'GET', self.sut.sessions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No GET request to %s found using account'
                      % self.sut.sessions_uri, result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
            'PATCH', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH request to account URI found',
                      result['msg'])

    def test_test_password_change_required_not_tested2(self):
        add_response(self.sut, self.account_uri,
                     'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
        sec.test_password_change_required(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
            'PATCH', self.account_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No PATCH request to %s found using account'
                      % self.account_uri, result['msg'])

    def test_test_priv_support_predefined_roles_pass(self):
        uri = '/redfish/v1/AccountsService/Roles/Operator/'
        payload = {
            'Id': 'Operator',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf',
                'ConfigureComponents'
            ],
        }
        add_response(self.sut, uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        sec.test_priv_support_predefined_roles(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_priv_support_predefined_roles_fail1(self):
        oper_uri = '/redfish/v1/AccountsService/Roles/Operator/'
        payload = {
            'Id': 'Operator',
            'AssignedPrivileges': [
                'Login',
                'ConfigureComponents'
                # ConfigureSelf missing for Operator
            ],
        }
        add_response(self.sut, oper_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf'
            ],
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        sec.test_priv_support_predefined_roles(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
            'GET', oper_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Predefined role Operator assigned privileges',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Predefined role Administrator not found',
                      result['msg'])

    def test_test_priv_support_predefined_roles_fail2(self):
        oper_uri = '/redfish/v1/AccountsService/Roles/Operator/'
        payload = {
            'Id': 'Operator',
            'AssignedPrivileges': [
                'Login',
                'ConfigureComponents',
                'ConfigureSelf',
                'ConfigureUsers'  # ConfigureUsers not allowed for Operator
            ],
        }
        add_response(self.sut, oper_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf',
                'NoAuth'  # NoAuth must not be in the privs
            ],
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        sec.test_priv_support_predefined_roles(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
            'GET', oper_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Predefined role Operator assigned privileges',
                      result['msg'])
        result = get_result(
            self.sut, Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
            'GET', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Predefined role ReadOnly assigned privileges',
                      result['msg'])

    def test_test_priv_predefined_roles_not_modifiable_not_tested1(self):
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Redefined role %s not found' % 'ReadOnly',
                      result['msg'])

    def test_test_priv_predefined_roles_not_modifiable_not_tested2(self):
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': []
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No AssignedPrivileges found in role %s' % 'ReadOnly',
                      result['msg'])

    def test_test_priv_predefined_roles_not_modifiable_not_tested3(self):
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        test_priv = 'RfProtoValTestPriv'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf',
                test_priv
            ]
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Test privilege %s already present in predefined role '
                      '%s' % (test_priv, 'ReadOnly'),
                      result['msg'])

    def test_test_priv_predefined_roles_not_modifiable_not_pass(self):
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        test_priv = 'RfProtoValTestPriv'
        etag = 'abcd1234'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf'
            ]
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        self.mock_session.get.return_value.ok = True
        self.mock_session.get.return_value.status_code = requests.codes.OK
        self.mock_session.get.return_value.headers = {'ETag': etag}
        self.mock_session.patch.return_value.ok = False
        self.mock_session.patch.return_value.status_code = (
            requests.codes.BAD_REQUEST)
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        self.mock_session.patch.assert_called_with(
            self.sut.rhost + ro_uri,
            json={'AssignedPrivileges': [{}, {}, test_priv]},
            headers={'If-Match': etag})
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_priv_predefined_roles_not_modifiable_not_fail1(self):
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        test_priv = 'RfProtoValTestPriv'
        etag = 'abcd1234'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf'
            ]
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        self.mock_session.get.return_value.ok = True
        self.mock_session.get.return_value.status_code = requests.codes.OK
        self.mock_session.get.return_value.headers = {'ETag': etag}
        self.mock_session.patch.return_value.ok = True
        self.mock_session.patch.return_value.status_code = requests.codes.OK
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        self.mock_session.patch.assert_called_with(
            self.sut.rhost + ro_uri,
            json={'AssignedPrivileges': [{}, {}, test_priv]},
            headers={'If-Match': etag})
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('to %s to modify the AssignedPrivileges of predefined '
                      'role %s succeeded with status %s; expected it to fail' %
                      (ro_uri, 'ReadOnly', requests.codes.OK),
                      result['msg'])

    def test_test_priv_predefined_roles_not_modifiable_not_fail2(self):
        ro_uri = '/redfish/v1/AccountsService/Roles/ReadOnly/'
        test_priv = 'RfProtoValTestPriv'
        etag = 'abcd1234'
        payload = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf',
                None
            ]
        }
        add_response(self.sut, ro_uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.ROLE, json=payload)
        mock_get1 = mock.MagicMock(spec=requests.Response)
        mock_get1.status_code = requests.codes.OK
        mock_get1.ok = True
        mock_get1.headers = {'ETag': etag}
        mock_get2 = mock.MagicMock(spec=requests.Response)
        mock_get2.status_code = requests.codes.OK
        mock_get2.ok = True
        mock_get2.headers = {'ETag': etag}
        mock_get2.json.return_value = {
            'Id': 'ReadOnly',
            'AssignedPrivileges': [
                'Login',
                'ConfigureSelf',
                test_priv
            ]
        }
        self.mock_session.get.side_effect = [mock_get1, mock_get2]
        self.mock_session.patch.return_value.ok = True
        self.mock_session.patch.return_value.status_code = requests.codes.OK
        sec.test_priv_predefined_roles_not_modifiable(self.sut)
        self.mock_session.patch.assert_called_with(
            self.sut.rhost + ro_uri,
            json={'AssignedPrivileges': [{}, {}, None]},
            headers={'If-Match': etag})
        result = get_result(
            self.sut, Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
            'PATCH', ro_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('to %s to modify the AssignedPrivileges of predefined '
                      'role %s succeeded with status %s; expected it to fail' %
                      (ro_uri, 'ReadOnly', requests.codes.OK),
                      result['msg'])

    def test_test_priv_one_role_per_user_pass(self):
        uri = '/redfish/v1/AccountsService/Accounts/carol/'
        payload = {
            'UserName': 'carol',
            'RoleId': 'ReadOnly'
        }
        add_response(self.sut, uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT, json=payload)
        sec.test_priv_one_role_per_user(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_ONE_ROLE_PRE_USER,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_priv_one_role_per_user_fail(self):
        uri = '/redfish/v1/AccountsService/Accounts/bob/'
        payload = {
            'UserName': 'bob'
        }
        add_response(self.sut, uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT, json=payload)
        sec.test_priv_one_role_per_user(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_ONE_ROLE_PRE_USER,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Account URI %s does not have a RoleId property' % uri,
                      result['msg'])

    def test_test_priv_roles_assigned_at_account_create_pass(self):
        user = 'rfpv4f0a'
        uri = '/redfish/v1/AccountsService/Accounts/%s/' % user
        payload = {
            'UserName': user,
            'RoleId': 'ReadOnly'
        }
        add_response(self.sut, uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT, json=payload)
        sec.test_priv_roles_assigned_at_account_create(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_priv_roles_assigned_at_account_create_fail(self):
        user = 'rfpv4f0a'
        uri = '/redfish/v1/AccountsService/Accounts/%s/' % user
        payload = {
            'UserName': user
        }
        add_response(self.sut, uri, 'GET', requests.codes.OK,
                     res_type=ResourceType.MANAGER_ACCOUNT, json=payload)
        sec.test_priv_roles_assigned_at_account_create(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Newly created account with username %s does not' % user,
                      result['msg'])

    def test_test_priv_operation_to_priv_mapping_not_tested(self):
        sec.test_priv_operation_to_priv_mapping(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
            'PATCH', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No response found attempting to PATCH an account using',
                      result['msg'])

    def test_test_priv_operation_to_priv_mapping_pass(self):
        uri = '/redfish/v1/AccountsService/Accounts/10/'
        headers = {'Authorization': 'Basic cmZwdmM1YmY6cDUzMDU5ZWE='}
        response = add_response(
            self.sut, uri, 'PATCH', requests.codes.UNAUTHORIZED,
            res_type=ResourceType.MANAGER_ACCOUNT,
            request_type=RequestType.MODIFY_OTHER)
        response.request.headers = headers
        sec.test_priv_operation_to_priv_mapping(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_priv_operation_to_priv_mapping_warn(self):
        uri = '/redfish/v1/AccountsService/Accounts/10/'
        headers = {'Authorization': 'Basic cmZwdmM1YmY6cDUzMDU5ZWE='}
        response = add_response(
            self.sut, uri, 'PATCH', requests.codes.FORBIDDEN,
            res_type=ResourceType.MANAGER_ACCOUNT,
            request_type=RequestType.MODIFY_OTHER)
        response.request.headers = headers
        sec.test_priv_operation_to_priv_mapping(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('failed with status %s, but expected it to fail with '
                      'status %s' % (requests.codes.FORBIDDEN,
                                     requests.codes.UNAUTHORIZED),
                      result['msg'])

    def test_test_priv_operation_to_priv_mapping_fail(self):
        uri = '/redfish/v1/AccountsService/Accounts/10/'
        headers = {'Authorization': 'Basic cmZwdmM1YmY6cDUzMDU5ZWE='}
        user = 'rfpvc5bf'
        response = add_response(
            self.sut, uri, 'PATCH', requests.codes.OK,
            res_type=ResourceType.MANAGER_ACCOUNT,
            request_type=RequestType.MODIFY_OTHER)
        response.request.headers = headers
        sec.test_priv_operation_to_priv_mapping(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
            'PATCH', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('PATCH request to account %s using credentials of other '
                      'user %s succeeded with status %s; expected it to fail '
                      'with status %s' % (uri, user, requests.codes.OK,
                                          requests.codes.UNAUTHORIZED),
                      result['msg'])

    def test_test_default_cert_replacement_pass1(self):
        uri1 = '/redfish/v1/CertificateService'
        payload = {
            'Actions': {
                '#CertificateService.ReplaceCertificate': {
                    'target': uri1 +
                    '/Actions/CertificateService.ReplaceCertificate',
                }
            }
        }
        add_response(self.sut, uri1, 'GET', requests.codes.OK, json=payload)
        self.sut.set_nav_prop_uri('CertificateService', uri1)
        uri2 = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
        add_response(self.sut, uri2, 'GET', requests.codes.OK)
        self.sut.add_cert(uri2, uri2 + '/1')
        self.sut.add_cert(uri2, uri2 + '/2')
        sec.test_default_cert_replacement(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
            'GET', self.sut.certificate_service_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_default_cert_replacement_pass2(self):
        uri1 = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
        headers1 = {'Allow': 'GET, POST, DELETE'}
        add_response(self.sut, uri1, 'GET', requests.codes.OK,
                     headers=headers1)
        uri2 = '/redfish/v1/Managers/2/NetworkProtocol/HTTPS/Certificates'
        headers2 = {}
        add_response(self.sut, uri2, 'GET', requests.codes.OK,
                     headers=headers2)
        self.sut.add_cert(uri1, uri1 + '/1')
        self.sut.add_cert(uri2, uri2 + '/1')
        sec.test_default_cert_replacement(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
            'GET', uri1)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        result = get_result(
            self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
            'GET', uri2)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_default_cert_replacement_fail(self):
        uri = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
        headers = {'Allow': 'GET, DELETE'}
        add_response(self.sut, uri, 'GET', requests.codes.OK, headers=headers)
        self.sut.add_cert(uri, uri + '/1')
        sec.test_default_cert_replacement(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('POST method not allowed for certificate collection %s'
                      % uri, result['msg'])

    def test_test_default_cert_replacement_not_tested1(self):
        sec.test_default_cert_replacement(self.sut)
        result = get_result(self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No certificates found on the service',
                      result['msg'])

    def test_test_default_cert_replacement_not_tested2(self):
        uri = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
        add_response(self.sut, uri, 'GET', requests.codes.NOT_FOUND)
        self.sut.add_cert(uri, uri + '/1')
        sec.test_default_cert_replacement(self.sut)
        result = get_result(
            self.sut, Assertion.SEC_DEFAULT_CERT_REPLACE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('request to certificate collection %s failed' % uri,
                      result['msg'])

    def test_test_security_details_cover(self):
        sec.test_security_details(self.sut)


if __name__ == '__main__':
    unittest.main()
