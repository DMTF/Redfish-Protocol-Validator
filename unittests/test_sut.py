# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions.constants import Assertion, ResourceType, Result
from assertions.system_under_test import SystemUnderTest
from unittests.utils import add_response


class Sut(TestCase):

    def setUp(self):
        super(Sut, self).setUp()
        self.rhost = 'http://127.0.0.1:8000'
        self.username = 'oper'
        self.password = 'xyzzy'
        self.version = '1.6.0'
        self.version_tuple = (1, 6, 0)
        self.sessions_uri = '/redfish/v1/sessions'
        self.active_session_uri = '/redfish/v1/sessions/12345'
        self.active_session_key = 'token98765'
        self.session = mock.Mock()
        self.systems_uri = '/redfish/v1/Systems'
        self.managers_uri = '/redfish/v1/Managers'
        self.chassis_uri = '/redfish/v1/Chassis'
        self.account_service_uri = '/redfish/v1/AccountService'
        self.accounts_uri = '/redfish/v1/accounts'
        self.roles_uri = '/redfish/v1/roles'
        self.cert_service_uri = '/redfish/v1/CertificateService'
        self.event_service_uri = '/redfish/v1/EventService'
        self.privilege_registry_uri = '/redfish/v1/AccountService/PrivilegeMap'
        self.sut = SystemUnderTest(self.rhost, self.username, self.password)
        self.sut.set_avoid_http_redirect(False)
        self.sut.set_version(self.version)
        self.sut.set_nav_prop_uri('Accounts', self.accounts_uri)
        self.sut.set_nav_prop_uri('Roles', self.roles_uri)
        self.sut.set_nav_prop_uri('Systems', self.systems_uri)
        self.sut.set_nav_prop_uri('Managers', self.managers_uri)
        self.sut.set_nav_prop_uri('Chassis', self.chassis_uri)
        self.sut.set_nav_prop_uri('AccountService', self.account_service_uri)
        self.sut.set_nav_prop_uri('CertificateService', self.cert_service_uri)
        self.sut.set_nav_prop_uri('EventService', self.event_service_uri)
        self.sut.set_nav_prop_uri('PrivilegeMap', self.privilege_registry_uri)
        add_response(self.sut, '/redfish/v1/foo',
                     status_code=requests.codes.NOT_FOUND)
        add_response(self.sut, '/redfish/v1/foo')
        add_response(self.sut, '/redfish/v1/bar')
        add_response(self.sut, '/redfish/v1/baz')
        add_response(self.sut, '/redfish/v1/foo', method='POST',
                     status_code=requests.codes.CREATED)
        add_response(self.sut, '/redfish/v1/bar', method='PATCH',
                     status_code=requests.codes.OK)
        add_response(self.sut, '/redfish/v1/accounts/1',
                     res_type=ResourceType.MANAGER_ACCOUNT)
        add_response(self.sut, '/redfish/v1/accounts/1', method='PATCH',
                     res_type=ResourceType.MANAGER_ACCOUNT)
        add_response(self.sut, '/redfish/v1/roles/1',
                     status_code=requests.codes.NOT_FOUND,
                     res_type=ResourceType.ROLE)
        self.sut.add_user({'UserName': 'alice', 'RoleId': 'Operator'})
        self.sut.add_user({'UserName': 'bob', 'RoleId': 'ReadOnly'})
        self.sut.add_role({'Id': 'ReadOnly',
                           'AssignedPrivileges': ['Login', 'ConfigureSelf'],
                           'OemPrivileges': ['ConfigureFoo']})
        self.sut.add_role({'RoleId': 'Operator',
                           'AssignedPrivileges': ['Login', 'ConfigureSelf',
                                                  'ConfigureComponents'],
                           'OemPrivileges': ['ConfigureBar']})
        self.sut.log(Result.PASS, 'GET', 200, '/redfish/v1/foo',
                     Assertion.PROTO_JSON_RFC, 'Test passed')
        self.sut.log(Result.PASS, 'GET', 200, '/redfish/v1/bar',
                     Assertion.PROTO_JSON_RFC, 'Test passed')
        self.sut.log(Result.FAIL, 'GET', 200, '/redfish/v1/accounts/1',
                     Assertion.PROTO_ETAG_ON_GET_ACCOUNT,
                     'did not return an ETag')
        self.headers = {
            'OData-Version': '4.0'
        }

    def test_init(self):
        self.assertEqual(self.sut.rhost, self.rhost)
        self.assertEqual(self.sut.username, self.username)
        self.assertEqual(self.sut.password, self.password)

    def test_set_version(self):
        self.sut.set_version('1.2.3')
        self.assertEqual(self.sut.version_tuple, (1, 2, 3))
        self.assertEqual(self.sut.version_string, '1.2.3')
        self.sut.set_version('1.2.3b')
        # '1.2.3b' will get a parse error, so will default to 1.0.0
        self.assertEqual(self.sut.version_tuple, (1, 0, 0))
        self.assertEqual(self.sut.version_string, '1.0.0')

    def test_version(self):
        self.assertEqual(self.sut.version_tuple, self.version_tuple)
        self.assertEqual(self.sut.version_string, self.version)

    def test_sessions_uri(self):
        self.sut.set_sessions_uri(self.sessions_uri)
        self.assertEqual(self.sut.sessions_uri, self.sessions_uri)

    def test_active_session_uri(self):
        self.sut._set_active_session_uri(self.active_session_uri)
        self.assertEqual(self.sut.active_session_uri, self.active_session_uri)
        self.sut._set_active_session_uri(None)
        self.assertIsNone(self.sut.active_session_uri)

    def test_active_session_key(self):
        self.sut._set_active_session_key(self.active_session_key)
        self.assertEqual(self.sut.active_session_key, self.active_session_key)

    def test_session(self):
        self.sut._set_session(self.session)
        self.assertEqual(self.sut.session, self.session)

    def test_systems_uri(self):
        self.assertEqual(self.sut.systems_uri, self.systems_uri)

    def test_managers_uri(self):
        self.assertEqual(self.sut.managers_uri, self.managers_uri)

    def test_chassis_uri(self):
        self.assertEqual(self.sut.chassis_uri, self.chassis_uri)

    def test_account_service_uri(self):
        self.assertEqual(self.sut.account_service_uri,
                         self.account_service_uri)

    def test_accounts_uri(self):
        self.assertEqual(self.sut.accounts_uri, self.accounts_uri)

    def test_roles_uri(self):
        self.assertEqual(self.sut.roles_uri, self.roles_uri)

    def test_cert_service_uri(self):
        self.assertEqual(self.sut.certificate_service_uri,
                         self.cert_service_uri)

    def test_event_service_uri(self):
        self.assertEqual(self.sut.event_service_uri,
                         self.event_service_uri)

    def test_privilege_registry_uri(self):
        self.assertEqual(self.sut.privilege_registry_uri,
                         self.privilege_registry_uri)

    @mock.patch('assertions.system_under_test.logging.error')
    def test_bad_nav_prop(self, mock_error):
        self.sut.set_nav_prop_uri('Foo', '/redfish/v1/Foo')
        self.assertEqual(mock_error.call_count, 1)
        args = mock_error.call_args[0]
        self.assertIn('set_nav_prop_uri() called with', args[0])

    def test_get_responses_by_method(self):
        responses = self.sut.get_responses_by_method('GET')
        self.assertEqual(len(responses), 5)
        responses = self.sut.get_responses_by_method('POST')
        self.assertEqual(len(responses), 1)
        responses = self.sut.get_responses_by_method('PATCH')
        self.assertEqual(len(responses), 2)
        responses = self.sut.get_responses_by_method(
            'GET', resource_type=ResourceType.MANAGER_ACCOUNT)
        self.assertEqual(len(responses), 1)
        responses = self.sut.get_responses_by_method(
            'PATCH', resource_type=ResourceType.MANAGER_ACCOUNT)
        self.assertEqual(len(responses), 1)
        responses = self.sut.get_responses_by_method(
            'GET', resource_type=ResourceType.ROLE)
        self.assertEqual(len(responses), 1)

    def test_get_response(self):
        response = self.sut.get_response('GET', '/redfish/v1/foo')
        self.assertEqual(response.status_code, requests.codes.OK)
        response = self.sut.get_response('POST', '/redfish/v1/foo')
        self.assertEqual(response.status_code, requests.codes.CREATED)
        response = self.sut.get_response('GET', '/redfish/v1/asdfgh')
        self.assertIsNone(response)
        response = self.sut.get_response('GET', '/redfish/v1/accounts/1')
        self.assertEqual(response.status_code, requests.codes.OK)
        response = self.sut.get_response('GET', '/redfish/v1/roles/1')
        self.assertEqual(response.status_code, requests.codes.NOT_FOUND)

    def test_get_all_responses(self):
        count = sum(1 for _ in self.sut.get_all_responses())
        self.assertEqual(count, 8)
        count = sum(1 for _ in self.sut.get_all_responses(
            resource_type=ResourceType.MANAGER_ACCOUNT
        ))
        self.assertEqual(count, 2)
        count = sum(1 for _ in self.sut.get_all_responses(
            resource_type=ResourceType.ROLE
        ))
        self.assertEqual(count, 1)

    def test_get_all_uris(self):
        uris = self.sut.get_all_uris()
        self.assertEqual(len(uris), 5)

    def test_get_all_uris_resource_type(self):
        uris = self.sut.get_all_uris(
            resource_type=ResourceType.MANAGER_ACCOUNT)
        self.assertEqual(len(uris), 1)

    def test_get_users(self):
        users = self.sut.get_users()
        self.assertEqual(users,
                         {'alice': {'UserName': 'alice', 'RoleId': 'Operator'},
                          'bob': {'UserName': 'bob', 'RoleId': 'ReadOnly'}})

    def test_get_user(self):
        user = self.sut.get_user('alice')
        self.assertEqual(user, {'UserName': 'alice', 'RoleId': 'Operator'})
        user = self.sut.get_user('bob')
        self.assertEqual(user, {'UserName': 'bob', 'RoleId': 'ReadOnly'})
        user = self.sut.get_user('carol')
        self.assertIsNone(user)

    def test_get_user_role(self):
        role = self.sut.get_user_role('alice')
        self.assertEqual(role, 'Operator')
        role = self.sut.get_user_role('bob')
        self.assertEqual(role, 'ReadOnly')
        role = self.sut.get_user_role('carol')
        self.assertIsNone(role)

    def test_get_user_privs(self):
        privs = self.sut.get_user_privs('alice')
        self.assertEqual(privs, ['Login', 'ConfigureSelf',
                                 'ConfigureComponents'])
        privs = self.sut.get_user_privs('bob')
        self.assertEqual(privs, ['Login', 'ConfigureSelf'])
        privs = self.sut.get_user_privs('carol')
        self.assertIsNone(privs)

    def test_get_user_oem_privs(self):
        privs = self.sut.get_user_oem_privs('alice')
        self.assertEqual(privs, ['ConfigureBar'])
        privs = self.sut.get_user_oem_privs('bob')
        self.assertEqual(privs, ['ConfigureFoo'])
        privs = self.sut.get_user_oem_privs('carol')
        self.assertIsNone(privs)

    def test_get_roles(self):
        roles = self.sut.get_roles()
        self.assertEqual(
            roles,
            {'ReadOnly': {'Id': 'ReadOnly',
                          'AssignedPrivileges': ['Login', 'ConfigureSelf'],
                          'OemPrivileges': ['ConfigureFoo']},
             'Operator': {'RoleId': 'Operator',
                          'AssignedPrivileges': ['Login', 'ConfigureSelf',
                                                 'ConfigureComponents'],
                          'OemPrivileges': ['ConfigureBar']}})

    def test_get_role(self):
        role = self.sut.get_role('ReadOnly')
        self.assertEqual(
            role,
            {'Id': 'ReadOnly',
             'AssignedPrivileges': ['Login', 'ConfigureSelf'],
             'OemPrivileges': ['ConfigureFoo']})
        role = self.sut.get_role('Operator')
        self.assertEqual(
            role,
            {'RoleId': 'Operator',
             'AssignedPrivileges': ['Login', 'ConfigureSelf',
                                    'ConfigureComponents'],
             'OemPrivileges': ['ConfigureBar']})
        role = self.sut.get_role('Custom1')
        self.assertIsNone(role)

    def test_get_role_privs(self):
        privs = self.sut.get_role_privs('ReadOnly')
        self.assertEqual(privs, ['Login', 'ConfigureSelf'])
        privs = self.sut.get_role_privs('Operator')
        self.assertEqual(privs, ['Login', 'ConfigureSelf',
                                 'ConfigureComponents'])
        privs = self.sut.get_role_privs('Custom1')
        self.assertIsNone(privs)

    def test_get_role_oem_privs(self):
        privs = self.sut.get_role_oem_privs('ReadOnly')
        self.assertEqual(privs, ['ConfigureFoo'])
        privs = self.sut.get_role_oem_privs('Operator')
        self.assertEqual(privs, ['ConfigureBar'])
        privs = self.sut.get_role_oem_privs('Custom1')
        self.assertIsNone(privs)

    def test_results(self):
        results = self.sut.results
        self.assertEqual(len(results.get(Assertion.PROTO_JSON_RFC)), 2)
        self.assertEqual(
            len(results.get(Assertion.PROTO_ETAG_ON_GET_ACCOUNT)), 1)
        self.assertEqual(
            len(results.get(Assertion.PROTO_JSON_ACCEPTED, {})), 0)

    def test_summary(self):
        self.assertEqual(self.sut.summary_count(Result.PASS), 2)
        self.assertEqual(self.sut.summary_count(Result.FAIL), 1)
        self.assertEqual(self.sut.summary_count(Result.WARN), 0)
        self.assertEqual(self.sut.summary_count(Result.NOT_TESTED), 0)

    @mock.patch('assertions.system_under_test.requests.get')
    def test_get_sessions_uri_default(self, mock_get):
        mock_get.return_value.status_code = requests.codes.OK
        uri = self.sut._get_sessions_uri(self.headers)
        self.assertEqual(uri, '/redfish/v1/SessionService/Sessions')

    @mock.patch('assertions.system_under_test.requests.get')
    def test_get_sessions_uri_via_links(self, mock_get):
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.OK
        response.json.return_value = {
            'Links': {
                'Sessions': {
                    '@odata.id': '/redfish/v1/Sessions'
                }
            }
        }
        mock_get.return_value = response
        uri = self.sut._get_sessions_uri(self.headers)
        self.assertEqual(uri, '/redfish/v1/Sessions')

    @mock.patch('assertions.system_under_test.requests.get')
    def test_get_sessions_uri_via_session_service(self, mock_get):
        response1 = mock.Mock(spec=requests.Response)
        response1.status_code = requests.codes.OK
        response1.json.return_value = {
            'SessionService': {
                '@odata.id': '/redfish/v1/SessionService'
            }
        }
        response2 = mock.Mock(spec=requests.Response)
        response2.status_code = requests.codes.OK
        response2.json.return_value = {
            'Sessions': {
                '@odata.id': '/redfish/v1/Sessions'
            }
        }
        mock_get.side_effect = [response1, response2]
        uri = self.sut._get_sessions_uri(self.headers)
        self.assertEqual(uri, '/redfish/v1/Sessions')

    @mock.patch('assertions.system_under_test.requests.get')
    @mock.patch('assertions.system_under_test.requests.post')
    @mock.patch('assertions.system_under_test.requests.Session')
    def test_login(self, mock_session, mock_post, mock_get):
        mock_get.return_value.status_code = requests.codes.OK
        post_resp = mock.Mock(spec=requests.Response)
        post_resp.status_code = requests.codes.OK
        token = '87a5cd20'
        url = 'http://127.0.0.1:8000/redfish/v1/sessions/1234'
        post_resp.headers = {
            'Location': url,
            'X-Auth-Token': token
        }
        mock_post.return_value = post_resp
        mock_session.return_value.headers = {}
        session = self.sut.login()
        self.assertIsNotNone(session)
        self.assertEqual(session.headers.get('X-Auth-Token'), token)
        self.assertEqual(self.sut.active_session_uri,
                         '/redfish/v1/sessions/1234')
        self.assertEqual(self.sut.active_session_key, token)

    @mock.patch('assertions.system_under_test.requests.get')
    @mock.patch('assertions.system_under_test.requests.post')
    def test_login_basic_auth(self, mock_post, mock_get):
        mock_get.return_value.status_code = requests.codes.OK
        post_resp = mock.Mock(spec=requests.Response)
        post_resp.status_code = requests.codes.BAD_REQUEST
        post_resp.ok = False
        mock_post.return_value = post_resp
        session = self.sut.login()
        self.assertIsNotNone(session)
        self.assertIsNone(self.sut.active_session_uri)
        self.assertIsNone(self.sut.active_session_key)
        self.assertEqual(session.auth, (self.sut.username, self.sut.password))

    @mock.patch('assertions.system_under_test.requests.get')
    @mock.patch('assertions.system_under_test.requests.post')
    @mock.patch('assertions.system_under_test.requests.Session')
    def test_login_no_token_header(self, mock_session, mock_post, mock_get):
        mock_get.return_value.status_code = requests.codes.OK
        post_resp = mock.Mock(spec=requests.Response)
        post_resp.status_code = requests.codes.OK
        url = 'http://127.0.0.1:8000/redfish/v1/sessions/1234'
        post_resp.headers = {
            'Location': url
        }
        mock_post.return_value = post_resp
        mock_session.return_value.headers = {}
        session = self.sut.login()
        self.assertIsNotNone(session)
        self.assertIsNone(session.headers.get('X-Auth-Token'))
        self.assertEqual(self.sut.active_session_uri,
                         '/redfish/v1/sessions/1234')
        self.assertIsNone(self.sut.active_session_key)
        self.assertEqual(session.auth, (self.sut.username, self.sut.password))

    def test_logout_pass(self):
        token = '87a5cd20'
        url = 'http://127.0.0.1:8000/redfish/v1/sessions/1234'
        self.sut._set_active_session_key(token)
        self.sut._set_active_session_uri(url)
        self.assertIsNotNone(self.sut.active_session_key)
        self.assertIsNotNone(self.sut.active_session_uri)
        session = mock.Mock(spec=requests.Session)
        session.delete.return_value.status_code = requests.codes.OK
        session.delete.return_value.ok = True
        self.sut._set_session(session)
        self.sut.logout()
        self.assertIsNone(self.sut.active_session_key)
        self.assertIsNone(self.sut.active_session_uri)

    @mock.patch('assertions.system_under_test.logging.error')
    def test_logout_fail(self, mock_error):
        token = '87a5cd20'
        url = 'http://127.0.0.1:8000/redfish/v1/sessions/1234'
        self.sut._set_active_session_key(token)
        self.sut._set_active_session_uri(url)
        session = mock.Mock(spec=requests.Session)
        session.delete.return_value.status_code = requests.codes.BAD_REQUEST
        session.delete.return_value.ok = False
        self.sut._set_session(session)
        self.sut.logout()
        self.assertEqual(mock_error.call_count, 1)


if __name__ == '__main__':
    unittest.main()
