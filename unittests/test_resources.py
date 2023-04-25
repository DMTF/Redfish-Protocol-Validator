# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from redfish_protocol_validator import resources
from redfish_protocol_validator.constants import RequestType
from redfish_protocol_validator.system_under_test import SystemUnderTest
from unittests.utils import add_response


class Resources(TestCase):
    def setUp(self):
        super(Resources, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.session)
        self.no_auth_session = mock.Mock(spec=requests.Session)
        add_response(self.sut, '/redfish/v1/', 'GET', requests.codes.OK)
        add_response(self.sut, self.sut.sessions_uri, 'GET', requests.codes.OK)
        add_response(self.sut, '/redfish/v1/', 'GET', requests.codes.OK,
                     request_type=RequestType.BASIC_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'GET', requests.codes.OK,
                     request_type=RequestType.BASIC_AUTH)
        add_response(self.sut, '/redfish/v1/', 'GET', requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, self.sut.sessions_uri, 'POST',
                     requests.codes.CREATED,
                     request_type=RequestType.NO_AUTH)
        add_response(self.sut, '/redfish/v1/AccountsService/Accounts/3',
                     'PATCH', requests.codes.NOT_ALLOWED,
                     request_type=RequestType.NO_AUTH)

    def test_get_default_resources(self):
        req = mock.Mock(spec=requests.Request)
        req.method = 'GET'
        res = mock.Mock(spec=requests.Response)
        res.status_code = requests.codes.OK
        res.json.return_value = {}
        res.request = req
        service_root = mock.Mock(spec=requests.Response)
        service_root.status_code = requests.codes.OK
        service_root.json.return_value = {
            'Systems': {
                '@odata.id': '/redfish/v1/Systems'
            },
            'Chassis': {
                '@odata.id': '/redfish/v1/Chassis'
            },
            'Managers': {
                '@odata.id': '/redfish/v1/Managers'
            },
            'AccountService': {
                '@odata.id': '/redfish/v1/AccountService'
            },
            'SessionService': {
                '@odata.id': '/redfish/v1/SessionService'
            },
            'Links': {
                'Sessions': {
                    '@odata.id': '/redfish/v1/SessionService/Sessions'
                }
            },
            'EventService': {
                '@odata.id': '/redfish/v1/EventService'
            },
            'CertificateService': {
                '@odata.id': '/redfish/v1/CertificateService'
            }
        }
        service_root.request = req
        coll1 = mock.Mock(spec=requests.Response)
        coll1.status_code = requests.codes.OK
        coll1.json.return_value = {
            'Members': [
                {
                    '@odata.id': '/redfish/v1/Foo/1'
                }
            ]
        }
        coll1.request = req
        coll2 = mock.Mock(spec=requests.Response)
        coll2.status_code = requests.codes.OK
        coll2.json.return_value = {
            'Members': [
                {
                    '@odata.id': '/redfish/v1/Foo/1'
                },
                {
                    '@odata.id': '/redfish/v1/Foo/2'
                }
            ]
        }
        coll2.request = req
        manager = mock.Mock(spec=requests.Response)
        manager.status_code = requests.codes.OK
        np_uri = '/redfish/v1/Managers/1/NetworkProtocol'
        manager.json.return_value = {
            'NetworkProtocol': {
                '@odata.id': np_uri
            }
        }
        manager.request = req
        net_proto = mock.Mock(spec=requests.Response)
        net_proto.status_code = requests.codes.OK
        net_proto.json.return_value = {
            'HTTPS': {
                'Certificates': {
                    '@odata.id': np_uri + '/HTTPS/Certificates'
                }
            },
        }
        net_proto.request = req
        account_service = mock.Mock(spec=requests.Response)
        account_service.status_code = requests.codes.OK
        account_service.json.return_value = {
            'Accounts': {
                '@odata.id': '/redfish/v1/AccountService/Accounts'
            },
            'Roles': {
                '@odata.id': '/redfish/v1/AccountService/Roles'
            },
            'PrivilegeMap': {
                '@odata.id': '/redfish/v1/AccountService/PrivilegeMap'
            }
        }
        account_service.request = req
        acct = mock.Mock(spec=requests.Response)
        acct.status_code = requests.codes.OK
        acct.json.return_value = {
            'UserName': self.sut.username,
            'RoleId': 'Administrator'
        }
        acct.request = req
        session_service = mock.Mock(spec=requests.Response)
        session_service.status_code = requests.codes.OK
        session_service.json.return_value = {
            'Sessions': {
                '@odata.id': '/redfish/v1/SessionService/Sessions'
            }
        }
        session_service.request = req
        event_service = mock.Mock(spec=requests.Response)
        event_service.status_code = requests.codes.OK
        event_service.json.return_value = {
            'ServerSentEventUri': '/redfish/v1/EventService/SSE',
            'Subscriptions': {
                "@odata.id": '/redfish/v1/EventService/Subscriptions'
            }
        }
        event_service.request = req

        self.session.get.side_effect = [
            res, res, res, res, res,
            service_root, coll1, res, coll1, res,
            coll1, manager, net_proto, coll1,
            account_service, coll1, acct, coll1, res,
            session_service, coll1, res,
            event_service, coll1, res, coll2,
            res
        ]
        resources.read_target_resources(
            self.sut, func=resources.get_default_resources)
        self.assertEqual(self.session.get.call_count, 27)

    def test_get_all_resources(self):
        with self.assertRaises(NotImplementedError):
            resources.read_target_resources(
                self.sut, func=resources.get_all_resources)

    def test_get_select_resources(self):
        with self.assertRaises(NotImplementedError):
            resources.read_target_resources(
                self.sut, func=resources.get_select_resources)

    def test_set_mfr_model_fw(self):
        uuid1 = "92384634-2938-2342-8820-489239905423"
        uuid2 = '85775665-c110-4b85-8989-e6162170b3ec'
        member1 = {
            'Manufacturer': 'Contoso',
            'Model': 'Contoso 2001',
            'FirmwareVersion': '1.01',
        }
        member2 = {
            'ServiceEntryPointUUID': uuid2,
            'Manufacturer': 'Contoso',
            'Model': 'Contoso 2002',
            'FirmwareVersion': '2.02',
        }
        member3 = {
            'ServiceEntryPointUUID': uuid1,
            'Manufacturer': 'Contoso',
            'Model': 'Contoso 2003',
            'FirmwareVersion': '3.03',
        }
        sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        for d in [member1, member2, member3]:
            sut.set_service_uuid(uuid1)
            resources.set_mfr_model_fw(sut, d)
        self.assertEqual(sut.firmware_version, '3.03')
        self.assertEqual(sut.manufacturer, 'Contoso')
        self.assertEqual(sut.model, 'Contoso 2003')
        sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        for d in [member1, member2, member3]:
            sut.set_service_uuid(uuid2)
            resources.set_mfr_model_fw(sut, d)
        self.assertEqual(sut.firmware_version, '2.02')
        self.assertEqual(sut.manufacturer, 'Contoso')
        self.assertEqual(sut.model, 'Contoso 2002')
        sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        for d in [member1, member2]:
            sut.set_service_uuid(uuid1)
            resources.set_mfr_model_fw(sut, d)
        self.assertEqual(sut.firmware_version, '1.01')
        self.assertEqual(sut.manufacturer, 'Contoso')
        self.assertEqual(sut.model, 'Contoso 2001')
        sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        for d in [member1, member2, member3]:
            sut.set_service_uuid(None)
            resources.set_mfr_model_fw(sut, d)
        self.assertEqual(sut.firmware_version, '1.01')
        self.assertEqual(sut.manufacturer, 'Contoso')
        self.assertEqual(sut.model, 'Contoso 2001')

    @mock.patch('redfish_protocol_validator.sessions.create_session')
    @mock.patch('redfish_protocol_validator.sessions.delete_session')
    @mock.patch('redfish_protocol_validator.accounts.add_account')
    @mock.patch('redfish_protocol_validator.accounts.patch_account')
    @mock.patch('redfish_protocol_validator.accounts.delete_account')
    @mock.patch('redfish_protocol_validator.accounts.password_change_required')
    def test_data_modification_requests(self, mock_pwd_change, mock_del_acct,
                                        mock_patch_acct, mock_add_acct,
                                        mock_delete_session,
                                        mock_create_session):
        session_uri = '/redfish/v1/SessionService/Sessions/7'
        mock_create_session.return_value = session_uri, 'my-token'
        user = 'rfpvc91c'
        pwd = 'pa325e6a'
        acct_uri = '/redfish/v1/AccountService/Accounts/5'
        mock_add_acct.return_value = (user, pwd, acct_uri)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.OK
        response.headers = {}
        response.json.return_value = {'PasswordChangeRequired': False}
        response.request = request
        self.session.get.return_value = response
        resources.data_modification_requests(self.sut)
        mock_create_session.assert_called_once_with(self.sut)
        mock_delete_session.assert_called_once_with(
            self.sut, self.session, session_uri,
            request_type=RequestType.NORMAL)
        mock_add_acct.assert_any_call(
            self.sut, self.session, request_type=RequestType.NORMAL)
        mock_patch_acct.assert_any_call(
            self.sut, self.session, acct_uri, request_type=RequestType.NORMAL)
        mock_del_acct.assert_any_call(
            self.sut, self.session, user, acct_uri,
            request_type=RequestType.NORMAL)
        self.assertEqual(mock_add_acct.call_count, 2)
        self.assertEqual(mock_patch_acct.call_count, 2)
        self.assertEqual(mock_del_acct.call_count, 2)
        self.assertEqual(mock_pwd_change.call_count, 1)

    @mock.patch('redfish_protocol_validator.sessions.logging.error')
    @mock.patch('redfish_protocol_validator.sessions.create_session')
    @mock.patch('redfish_protocol_validator.sessions.delete_session')
    @mock.patch('redfish_protocol_validator.accounts.add_account')
    @mock.patch('redfish_protocol_validator.accounts.patch_account')
    @mock.patch('redfish_protocol_validator.accounts.delete_account')
    @mock.patch('redfish_protocol_validator.accounts.password_change_required')
    def test_data_modification_requests_exception(
            self, mock_pwd_change, mock_del_acct, mock_patch_acct,
            mock_add_acct, mock_delete_session, mock_create_session,
            mock_error):
        session_uri = '/redfish/v1/SessionService/Sessions/7'
        mock_create_session.return_value = session_uri, 'my-token'
        user = 'rfpvc91c'
        pwd = 'pa325e6a'
        acct_uri = '/redfish/v1/AccountService/Accounts/5'
        mock_add_acct.return_value = (user, pwd, acct_uri)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.OK
        response.headers = {}
        response.json.return_value = {'PasswordChangeRequired': False}
        response.request = request
        self.session.get.return_value = response
        mock_patch_acct.side_effect = ConnectionError
        resources.data_modification_requests(self.sut)
        mock_create_session.assert_called_once_with(self.sut)
        mock_delete_session.assert_called_once_with(
            self.sut, self.session, session_uri,
            request_type=RequestType.NORMAL)
        mock_add_acct.assert_any_call(
            self.sut, self.session, request_type=RequestType.NORMAL)
        mock_patch_acct.assert_any_call(
            self.sut, self.session, acct_uri, request_type=RequestType.NORMAL)
        mock_del_acct.assert_any_call(
            self.sut, self.session, user, acct_uri,
            request_type=RequestType.NORMAL)
        self.assertEqual(mock_add_acct.call_count, 1)
        self.assertEqual(mock_patch_acct.call_count, 1)
        self.assertEqual(mock_del_acct.call_count, 1)
        self.assertEqual(mock_pwd_change.call_count, 1)
        args = mock_error.call_args[0]
        self.assertIn('Caught exception while creating or patching', args[0])

    @mock.patch('redfish_protocol_validator.sessions.create_session')
    @mock.patch('redfish_protocol_validator.sessions.delete_session')
    @mock.patch('redfish_protocol_validator.accounts.add_account')
    @mock.patch('redfish_protocol_validator.accounts.patch_account')
    @mock.patch('redfish_protocol_validator.accounts.delete_account')
    def test_data_modification_requests_no_auth(
            self, mock_del_acct, mock_patch_acct, mock_add_acct,
            mock_delete_session, mock_create_session):
        session_uri = '/redfish/v1/SessionService/Sessions/8'
        mock_create_session.return_value = session_uri, 'my-token'
        user = 'rfpvc91c'
        pwd = 'pa325e6a'
        acct_uri = '/redfish/v1/AccountService/Accounts/6'
        mock_add_acct.side_effect = [
            (user, pwd, None),
            (user, pwd, acct_uri)
        ]
        mock_delete_session.return_value.ok = False
        mock_add_acct.return_value = ()
        resources.data_modification_requests_no_auth(
            self.sut, self.no_auth_session)
        mock_create_session.assert_called_once_with(self.sut)
        self.assertEqual(mock_delete_session.call_count, 2)
        mock_delete_session.assert_called_with(
            self.sut, self.session, session_uri,
            request_type=RequestType.NORMAL)
        self.assertEqual(mock_add_acct.call_count, 2)
        mock_add_acct.assert_called_with(
            self.sut, self.session, request_type=RequestType.NORMAL)
        mock_patch_acct.assert_called_once_with(
            self.sut, self.no_auth_session, acct_uri,
            request_type=RequestType.NO_AUTH)
        self.assertEqual(mock_del_acct.call_count, 2)
        mock_del_acct.assert_called_with(
            self.sut, self.session, user, acct_uri,
            request_type=RequestType.NORMAL)

    @mock.patch('redfish_protocol_validator.sessions.logging.error')
    @mock.patch('redfish_protocol_validator.accounts.add_account')
    def test_patch_other_account_exception(
            self, mock_add_acct, mock_error):
        user = 'rfpvc91c'
        pwd = 'pa325e6a'
        mock_add_acct.side_effect = ConnectionError
        resources.patch_other_account(self.sut, self.session, user, pwd)
        args = mock_error.call_args[0]
        self.assertIn('Caught exception while creating or patching', args[0])

    def test_unsupported_requests(self):
        request = mock.Mock(spec=requests.Request)
        request.method = 'DELETE'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.METHOD_NOT_ALLOWED
        response.request = request
        self.session.request.return_value = response
        resources.unsupported_requests(self.sut)
        self.session.request.called_once_with(
            'DELETE', self.sut.rhost + '/redfish/v1/')

    @mock.patch('redfish_protocol_validator.sessions.requests.get')
    def test_basic_auth_requests(self, mock_get):
        headers = {'OData-Version': '4.0'}
        mock_get.return_value.status_code = requests.codes.OK
        resources.basic_auth_requests(self.sut)
        mock_get.assert_any_call(self.sut.rhost + self.sut.sessions_uri,
                                 headers=headers, auth=(self.sut.username,
                                                        self.sut.password),
                                 verify=self.sut.verify)
        responses = self.sut.get_responses_by_method(
            'GET', request_type=RequestType.BASIC_AUTH)
        self.assertEqual(len(responses), 2)

    @mock.patch('redfish_protocol_validator.sessions.requests.get')
    def test_http_requests_https_scheme(self, mock_get):
        headers = {'OData-Version': '4.0'}
        if self.sut.scheme == 'https':
            http_rhost = 'http' + self.sut.rhost[5:]
        else:
            http_rhost = self.sut.rhost
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.OK
        response.request = request
        mock_get.return_value = response
        resources.http_requests(self.sut)
        mock_get.assert_any_call(http_rhost + self.sut.sessions_uri,
                                 headers=headers, auth=(self.sut.username,
                                                        self.sut.password),
                                 verify=self.sut.verify)
        responses = self.sut.get_responses_by_method(
            'GET', request_type=RequestType.HTTP_BASIC_AUTH)
        self.assertEqual(len(responses), 1)
        responses = self.sut.get_responses_by_method(
            'GET', request_type=RequestType.HTTP_NO_AUTH)
        self.assertEqual(len(responses), 2)

    @mock.patch('redfish_protocol_validator.resources.logging.warning')
    @mock.patch('redfish_protocol_validator.resources.requests.get')
    def test_http_requests_https_scheme_exception(self, mock_get, mock_warn):
        mock_get.side_effect = ConnectionError
        mock_sut = mock.MagicMock(spec=SystemUnderTest)
        mock_sut.scheme = 'https'
        mock_sut.avoid_http_redirect = False
        resources.http_requests(mock_sut)
        args = mock_warn.call_args[0]
        self.assertIn('Caught ConnectionError while trying to trigger',
                      args[0])

    @mock.patch('redfish_protocol_validator.sessions.requests.get')
    def test_http_requests_http_scheme(self, mock_get):
        sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        add_response(sut, '/redfish/v1/', 'GET', requests.codes.OK,
                     request_type=RequestType.NO_AUTH)
        add_response(sut, sut.sessions_uri, 'GET', requests.codes.OK,
                     request_type=RequestType.BASIC_AUTH)
        add_response(sut, sut.sessions_uri, 'GET',
                     requests.codes.UNAUTHORIZED,
                     request_type=RequestType.NO_AUTH)
        mock_get.return_value.status_code = requests.codes.OK
        resources.http_requests(sut)
        responses = sut.get_responses_by_method(
            'GET', request_type=RequestType.HTTP_BASIC_AUTH)
        self.assertEqual(len(responses), 1)
        responses = sut.get_responses_by_method(
            'GET', request_type=RequestType.HTTP_NO_AUTH)
        self.assertEqual(len(responses), 2)

    @mock.patch('redfish_protocol_validator.sessions.logging.warning')
    def test_http_requests_other_scheme(self, mock_warning):
        sut = SystemUnderTest('ftp://127.0.0.1:8000', 'oper', 'xyzzy')
        resources.http_requests(sut)
        args = mock_warning.call_args[0]
        self.assertIn('Unexpected scheme (ftp)', args[0])

    @mock.patch('redfish_protocol_validator.sessions.requests.get')
    def test_bad_auth_requests(self, mock_get):
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response = mock.Mock(spec=requests.Response)
        response.status_code = requests.codes.UNAUTHORIZED
        response.request = request
        mock_get.return_value = response
        resources.bad_auth_requests(self.sut)
        self.assertEqual(mock_get.call_count, 2)
        responses = self.sut.get_responses_by_method(
            'GET', request_type=RequestType.BAD_AUTH)
        self.assertEqual(len(responses), 2)

    def test_read_uris_no_auth(self):
        session = mock.Mock(spec=requests.Session)
        session.get.return_value.status_code = requests.codes.OK
        resources.read_uris_no_auth(self.sut, session)
        self.assertEqual(session.get.call_count, 2)


if __name__ == '__main__':
    unittest.main()
