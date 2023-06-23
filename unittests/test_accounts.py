# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import string
import unittest
from unittest import mock, TestCase

import requests

from redfish_protocol_validator import accounts
from redfish_protocol_validator.constants import ResourceType
from redfish_protocol_validator.system_under_test import SystemUnderTest
from unittests.utils import add_response


class Accounts(TestCase):

    def setUp(self):
        super(Accounts, self).setUp()
        self.sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.accounts_uri = '/redfish/v1/AccountService/Accounts'
        self.account_uri1 = '/redfish/v1/AccountService/Accounts/1'
        self.account_uri2 = '/redfish/v1/AccountService/Accounts/2'
        self.account_uri3 = '/redfish/v1/AccountService/Accounts/3'
        self.roles_uri = '/redfish/v1/AccountService/Roles'
        self.role_uri1 = '/redfish/v1/AccountService/Roles/ReadOnlyUser'
        self.role_uri2 = '/redfish/v1/AccountService/Roles/Administrator'
        self.sut.set_nav_prop_uri('Accounts', self.accounts_uri)
        self.sut.set_nav_prop_uri('Roles', self.roles_uri)
        self.session = mock.MagicMock(spec=requests.Session)
        payload = {
            'Members': [
                {'@odata.id': self.account_uri1},
                {'@odata.id': self.account_uri2},
                {'@odata.id': self.account_uri3}
            ]
        }
        add_response(self.sut, self.accounts_uri, json=payload)
        payload = {'UserName': 'Administrator', 'Enabled': True}
        add_response(self.sut, self.account_uri1, json=payload,
                     res_type=ResourceType.MANAGER_ACCOUNT)
        payload = {'UserName': '', 'Enabled': False}
        add_response(self.sut, self.account_uri3, json=payload,
                     res_type=ResourceType.MANAGER_ACCOUNT)
        payload = {
            'Members': [
                {'@odata.id': self.role_uri1},
                {'@odata.id': self.role_uri2}
            ]
        }
        add_response(self.sut, self.roles_uri, json=payload)
        payload = {'Id': 'ReadOnly'}
        add_response(self.sut, self.role_uri1, json=payload,
                     res_type=ResourceType.ROLE)

    def test_get_user_names(self):
        users = accounts.get_user_names(self.sut, self.session)
        self.assertEqual(users, {'Administrator'})

    def test_select_standard_role_pass(self):
        role = accounts.select_standard_role(self.sut, self.session)
        self.assertEqual(role, 'ReadOnly')

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_select_standard_role_fail(self, mock_logging_error):
        payload = {'Id': 'Guest'}
        add_response(self.sut, self.role_uri1, json=payload,
                     res_type=ResourceType.ROLE)
        role = accounts.select_standard_role(self.sut, self.session)
        self.assertIsNone(role)
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('Predefined role "ReadOnly" not found', args[0])

    def test_new_username(self):
        existing = {'admin', 'root', 'alice', 'bob'}
        user1 = accounts.new_username(existing)
        self.assertFalse(user1 in existing)
        self.assertTrue(user1.startswith('rfpv'))
        self.assertEqual(len(user1), 8)
        existing.add(user1)
        user2 = accounts.new_username(existing)
        self.assertFalse(user2 in existing)
        self.assertTrue(user2.startswith('rfpv'))
        self.assertEqual(len(user2), 8)
        self.assertNotEqual(user1, user2)

    def test_new_password(self):
        pass1 = accounts.new_password(self.sut)
        self.assertEqual(len(pass1), 16)
        self.assertTrue(set(pass1).intersection(set(string.ascii_uppercase)))
        self.assertTrue(set(pass1).intersection(set(string.ascii_lowercase)))
        self.assertTrue(set(pass1).intersection(set(string.digits)))
        pass2 = accounts.new_password(self.sut)
        self.assertEqual(len(pass2), 16)
        self.assertTrue(set(pass2).intersection(set(string.ascii_uppercase)))
        self.assertTrue(set(pass2).intersection(set(string.ascii_lowercase)))
        self.assertTrue(set(pass2).intersection(set(string.digits)))
        self.assertNotEqual(pass1, pass2)
        pass3 = accounts.new_password(self.sut, symbols=1)
        self.assertEqual(len(pass3), 16)
        self.assertTrue(set(pass3).intersection(set(string.ascii_uppercase)))
        self.assertTrue(set(pass3).intersection(set(string.ascii_lowercase)))
        self.assertTrue(set(pass3).intersection(set(string.digits)))
        self.assertTrue(set(pass3).intersection(set('_-.')))

    def test_add_account_via_patch_pass(self):
        self.session.post.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertEqual(len(user), 8)
        self.assertTrue(user.startswith('rfpv'))
        self.assertEqual(uri, self.account_uri3)

    def test_add_account_via_patch_enable(self):
        etag = '0123456789abcdef'
        self.session.get.return_value.status_code = requests.codes.OK
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {'Enabled': False}
        self.session.get.return_value.headers = {'ETag': etag}
        self.session.post.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.session.patch.assert_called_with(
            self.sut.rhost + self.account_uri3, json={'Enabled': True},
            headers={'If-Match': etag})

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_add_account_via_patch_fail1(self, mock_logging_error):
        payload = {'UserName': 'alice', 'Enabled': True}
        add_response(self.sut, self.account_uri3, json=payload,
                     res_type=ResourceType.MANAGER_ACCOUNT)
        self.session.post.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertIsNone(user)
        self.assertIsNone(uri)
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('No empty account slot found', args[0])

    def test_add_account_via_patch_fail2(self):
        self.session.post.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = (
            requests.codes.BAD_REQUEST)
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertIsNone(uri)

    def test_add_account_pass(self):
        new_uri = '/redfish/v1/AccountService/Accounts/4'
        self.session.post.return_value.status_code = requests.codes.CREATED
        self.session.post.return_value.headers = {
            'Location': self.sut.rhost + new_uri
        }
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertEqual(len(user), 8)
        self.assertTrue(user.startswith('rfpv'))
        self.assertEqual(uri, new_uri)

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_add_account_no_collection(self, mock_logging_error):
        self.sut.set_nav_prop_uri('Accounts', None)
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertIsNone(user)
        self.assertIsNone(uri)
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('No accounts collection found', args[0])

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_add_account_collection_get_fail(self, mock_logging_error):
        add_response(self.sut, self.accounts_uri, json={},
                     status_code=requests.codes.NOT_FOUND)
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertIsNone(user)
        self.assertIsNone(uri)
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('Accounts collection could not be read', args[0])

    def test_add_account_collection_allow_header_post(self):
        payload = {
            'Members': [
                {'@odata.id': self.account_uri1},
                {'@odata.id': self.account_uri2},
                {'@odata.id': self.account_uri3}
            ]
        }
        headers = {'Allow': 'GET, POST'}
        add_response(self.sut, self.accounts_uri, json=payload,
                     headers=headers)
        new_uri = '/redfish/v1/AccountService/Accounts/4'
        self.session.post.return_value.status_code = requests.codes.CREATED
        self.session.post.return_value.headers = {
            'Location': self.sut.rhost + new_uri
        }
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertEqual(len(user), 8)
        self.assertTrue(user.startswith('rfpv'))
        self.assertEqual(uri, new_uri)

    def test_add_account_collection_allow_header_no_post(self):
        payload = {
            'Members': [
                {'@odata.id': self.account_uri1},
                {'@odata.id': self.account_uri2},
                {'@odata.id': self.account_uri3}
            ]
        }
        headers = {'Allow': 'GET'}
        add_response(self.sut, self.accounts_uri, json=payload,
                     headers=headers)
        self.session.patch.return_value.status_code = requests.codes.OK
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertEqual(len(user), 8)
        self.assertTrue(user.startswith('rfpv'))
        self.assertEqual(uri, self.account_uri3)

    def test_add_account_no_location_header(self):
        new_uri = '/redfish/v1/AccountService/Accounts/4'
        self.session.post.return_value.status_code = requests.codes.CREATED
        self.session.post.return_value.headers = {}
        self.session.post.return_value.json.return_value = {
            '@odata.id': new_uri
        }
        user, pwd, uri = accounts.add_account(self.sut, self.session)
        self.assertEqual(len(user), 8)
        self.assertTrue(user.startswith('rfpv'))
        self.assertEqual(uri, new_uri)

    def test_patch_account1(self):
        self.session.get.return_value.status_code = requests.codes.OK
        self.session.get.return_value.ok = True
        self.session.get.return_value.headers = {}
        uri = '/redfish/v1/AccountService/Accounts/4'
        accounts.patch_account(self.sut, self.session, uri)
        self.assertEqual(self.session.patch.call_count, 4)

    def test_patch_account2(self):
        self.session.get.return_value.status_code = requests.codes.OK
        self.session.get.return_value.ok = True
        self.session.get.return_value.headers = {'ETag': '0123456789abcdef'}
        uri = '/redfish/v1/AccountService/Accounts/4'
        accounts.patch_account(self.sut, self.session, uri)
        self.assertEqual(self.session.patch.call_count, 5)

    def test_delete_account_via_patch_pass(self):
        self.session.delete.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        accounts.delete_account(self.sut, self.session, 'Administrator',
                                self.account_uri1)
        self.assertEqual(self.session.delete.call_count, 1)
        self.assertEqual(self.session.patch.call_count, 1)

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_delete_account_via_patch_bad_username(self, mock_logging_error):
        self.session.delete.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        accounts.delete_account(self.sut, self.session, 'bad_name',
                                self.account_uri1)
        self.assertEqual(self.session.delete.call_count, 1)
        self.session.patch.assert_not_called()
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('did not match expected username', args[0])

    @mock.patch('redfish_protocol_validator.accounts.logging.error')
    def test_delete_account_via_patch_get_failed(self, mock_logging_error):
        self.session.delete.return_value.status_code = (
            requests.codes.METHOD_NOT_ALLOWED)
        self.session.patch.return_value.status_code = requests.codes.OK
        payload = {'UserName': 'Administrator', 'Enabled': True}
        add_response(self.sut, self.account_uri1, json=payload,
                     status_code=requests.codes.NOT_FOUND,
                     res_type=ResourceType.MANAGER_ACCOUNT)

        accounts.delete_account(self.sut, self.session, 'Administrator',
                                self.account_uri1)
        self.assertEqual(self.session.delete.call_count, 1)
        self.session.patch.assert_not_called()
        self.assertEqual(mock_logging_error.call_count, 1)
        args = mock_logging_error.call_args[0]
        self.assertIn('could not read account uri', args[0])

    def test_delete_account_pass(self):
        self.session.delete.return_value.status_code = requests.codes.OK
        accounts.delete_account(self.sut, self.session, 'Administrator',
                                self.account_uri1)
        self.assertEqual(self.session.delete.call_count, 1)

    def test_delete_account_allow_header_delete(self):
        payload = {'UserName': 'Administrator', 'Enabled': True}
        headers = {'Allow': 'GET, POST, DELETE'}
        add_response(self.sut, self.account_uri1, json=payload,
                     status_code=requests.codes.NOT_FOUND,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     headers=headers)
        self.session.delete.return_value.status_code = requests.codes.OK
        accounts.delete_account(self.sut, self.session, 'Administrator',
                                self.account_uri1)
        self.assertEqual(self.session.delete.call_count, 1)

    def test_delete_account_allow_header_no_delete(self):
        payload = {'UserName': 'Administrator', 'Enabled': True}
        headers = {'Allow': 'GET, POST'}
        add_response(self.sut, self.account_uri1, json=payload,
                     res_type=ResourceType.MANAGER_ACCOUNT,
                     headers=headers)
        self.session.patch.return_value.status_code = requests.codes.OK
        accounts.delete_account(self.sut, self.session, 'Administrator',
                                self.account_uri1)
        self.assertEqual(self.session.patch.call_count, 1)

    @mock.patch('redfish_protocol_validator.accounts.requests.get')
    @mock.patch('redfish_protocol_validator.accounts.requests.post')
    @mock.patch('redfish_protocol_validator.accounts.requests.patch')
    def test_password_change_required1(self, mock_patch, mock_post, mock_get):
        user = 'bob'
        pwd = 'xyzzy'
        payload = {
            'PasswordChangeRequired': True
        }
        etag = 'A89B031B62'
        accounts.password_change_required(self.sut, self.session, user, pwd,
                                          self.account_uri1, payload, etag)
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(mock_patch.call_count, 1)

    @mock.patch('redfish_protocol_validator.accounts.requests.get')
    @mock.patch('redfish_protocol_validator.accounts.requests.post')
    @mock.patch('redfish_protocol_validator.accounts.requests.patch')
    def test_password_change_required2(self, mock_patch, mock_post, mock_get):
        user = 'bob'
        pwd = 'xyzzy'
        payload = {
            'PasswordChangeRequired': False
        }
        etag = 'A89B031B62'
        request = mock.Mock(spec=requests.Request)
        request.method = 'PATCH'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.BAD_REQUEST
        response.ok = False
        response.headers = {}
        response.request = request

        self.session.patch.return_value = response
        accounts.password_change_required(self.sut, self.session, user, pwd,
                                          self.account_uri1, payload, etag)
        self.assertEqual(mock_get.call_count, 0)
        self.assertEqual(mock_post.call_count, 0)
        self.assertEqual(mock_patch.call_count, 0)

    @mock.patch('redfish_protocol_validator.accounts.requests.get')
    @mock.patch('redfish_protocol_validator.accounts.requests.post')
    @mock.patch('redfish_protocol_validator.accounts.requests.patch')
    def test_password_change_required_no_prop(self, mock_patch, mock_post,
                                              mock_get):
        user = 'bob'
        pwd = 'xyzzy'
        payload = {}
        etag = 'A89B031B62'
        accounts.password_change_required(self.sut, self.session, user, pwd,
                                          self.account_uri1, payload, etag)
        self.assertEqual(mock_get.call_count, 0)
        self.assertEqual(mock_post.call_count, 0)
        self.assertEqual(mock_patch.call_count, 0)


if __name__ == '__main__':
    unittest.main()
