# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions import service_responses as resp
from assertions.system_under_test import SystemUnderTest


class ServiceResponses(TestCase):

    def setUp(self):
        super(ServiceResponses, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)

    def test_test_service_responses_cover(self):
        resp.test_service_responses(self.sut)


if __name__ == '__main__':
    unittest.main()
