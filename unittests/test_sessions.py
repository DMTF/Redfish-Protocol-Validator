# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from redfish_protocol_validator import sessions
from redfish_protocol_validator.system_under_test import SystemUnderTest


class Sessions(TestCase):
    def setUp(self):
        super(Sessions, self).setUp()
        self.sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.set_sessions_uri('/redfish/v1/SessionService/Sessions')
        self.headers = {
            'OData-Version': '4.0'
        }

    @mock.patch('redfish_protocol_validator.sessions.requests.post')
    def test_bad_login(self, mock_post):
        post_resp = mock.Mock(spec=requests.Response)
        post_resp.status_code = requests.codes.BAD_REQUEST
        request = mock.Mock(spec=requests.Request)
        request.method = 'POST'
        post_resp.request = request
        mock_post.return_value = post_resp
        sessions.bad_login(self.sut)
        self.assertEqual(mock_post.call_count, 1)

    @mock.patch('redfish_protocol_validator.sessions.requests.post')
    def test_create_session(self, mock_post):
        token = '87a5cd20'
        url = 'http://127.0.0.1:8000/redfish/v1/sessions/1234'
        uri = '/redfish/v1/sessions/1234'
        mock_post.return_value.status_code = requests.codes.OK
        mock_post.return_value.headers = {
            'Location': url,
            'X-Auth-Token': token
        }
        new_uri, _ = sessions.create_session(self.sut)
        self.assertEqual(uri, new_uri)

    @mock.patch('redfish_protocol_validator.sessions.requests.post')
    @mock.patch('redfish_protocol_validator.sessions.logging.warning')
    def test_create_session_post_fail(self, mock_warning, mock_post):
        mock_post.return_value.status_code = requests.codes.BAD_REQUEST
        mock_post.return_value.ok = False
        sessions.create_session(self.sut)
        self.assertEqual(mock_warning.call_count, 1)
        args = mock_warning.call_args[0]
        self.assertIn('session POST status: 400', args[0])

    def test_delete_session(self):
        uri = '/redfish/v1/sessions/1234'
        session = mock.Mock(spec=requests.Session)
        session.delete.return_value.status_code = requests.codes.OK
        sessions.delete_session(self.sut, session, uri)
        session.delete.assert_called_once_with(self.sut.rhost + uri)

    @mock.patch('redfish_protocol_validator.sessions.requests.Session')
    def test_no_auth_session(self, mock_session):
        session = mock.Mock(spec=requests.Session)
        mock_session.return_value = session
        sessions.no_auth_session(self.sut)
        self.assertEqual(mock_session.call_count, 1)
        self.assertEqual(self.sut.verify, session.verify)


if __name__ == '__main__':
    unittest.main()
