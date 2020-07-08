# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock, TestCase

from assertions.constants import Assertion, Result
from assertions.report import html_report, tsv_report
from assertions.system_under_test import SystemUnderTest


class Report(TestCase):
    def setUp(self):
        super(Report, self).setUp()
        self.report_dir = Path('reports')
        self.current_time = datetime.now()
        self.sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        self.sut.log(Result.PASS, 'GET', 200, '/redfish/v1/foo',
                     Assertion.PROTO_JSON_RFC, 'Test passed')
        self.sut.log(Result.PASS, 'GET', 200, '/redfish/v1/bar',
                     Assertion.PROTO_JSON_RFC, 'Test passed')
        self.sut.log(Result.FAIL, 'GET', 200, '/redfish/v1/accounts/1',
                     Assertion.PROTO_ETAG_ON_GET_ACCOUNT,
                     'did not return an ETag')
        self.sut.log(Result.WARN, 'GET', 204, '/redfish/v1/baz',
                     Assertion.PROTO_STD_URIS_SUPPORTED,
                     'some warning message')

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_tsv_report(self, mock_file):
        handle = mock_file()
        tsv_report(self.sut, self.report_dir, self.current_time)
        # one write() for the header plus one for each of the four log results
        self.assertEqual(handle.write.call_count, 5)

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_html_report(self, mock_file):
        handle = mock_file()
        html_report(self.sut, self.report_dir, self.current_time, '0.6.0')
        # HTML report is generated with one write() call
        self.assertEqual(handle.write.call_count, 1)


if __name__ == '__main__':
    unittest.main()
