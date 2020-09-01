# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions import protocol_details as proto
from assertions.constants import Assertion, RequestType, ResourceType, Result
from assertions.system_under_test import SystemUnderTest
from unittests.utils import add_response, get_result


class ProtocolDetails(TestCase):

    def _add_get_responses(self, status=requests.codes.OK):
        add_response(self.sut, '/redfish', 'GET', status,
                     json={'v1': '/redfish/v1/'})
        add_response(self.sut, '/redfish/v1/', 'GET', status,
                     json={'foo': 'bar'})
        add_response(self.sut, '/redfish/v1', 'GET', status,
                     json={'foo': 'bar'})
        add_response(self.sut, '/redfish/v1/odata', 'GET', status,
                     json={'foo': 'bar'})
        add_response(self.sut, '/redfish/v1/AccountService/Accounts/1', 'GET',
                     status, json={'foo': 'bar'},
                     res_type=ResourceType.MANAGER_ACCOUNT)
        add_response(self.sut, '/redfish/v1/$metadata', 'GET', status,
                     text='<Edmx><DataServices></DataServices></Edmx>')
        add_response(self.sut, self.sut.server_sent_event_uri, 'GET', status,
                     text=': stream keep-alive',
                     request_type=RequestType.STREAMING)

    def setUp(self):
        super(ProtocolDetails, self).setUp()
        self.sut = SystemUnderTest('http://127.0.0.1:8000', 'oper', 'xyzzy')
        sse_uri = '/redfish/v1/EventService/SSE'
        self.sut.set_server_sent_event_uri(sse_uri)
        self._add_get_responses(status=requests.codes.OK)
        add_response(self.sut, '/redfish/v1/AccountService/Accounts', 'POST',
                     requests.codes.CREATED, json={'foo': 'bar'},
                     request_payload='{"UserName": "bob"}')

    def test_split_path(self):
        path, query, frag = proto.split_path('/foo/Bar/x?q1#f1')
        self.assertEqual(path, '/foo/Bar/x')
        self.assertEqual(query, 'q1')
        self.assertEqual(frag, 'f1')
        path, query, frag = proto.split_path('/foo/Bar/x#f2')
        self.assertEqual(path, '/foo/Bar/x')
        self.assertEqual(query, '')
        self.assertEqual(frag, 'f2')
        path, query, frag = proto.split_path('/foo/Bar/x?q2')
        self.assertEqual(path, '/foo/Bar/x')
        self.assertEqual(query, 'q2')
        self.assertEqual(frag, '')
        path, query, frag = proto.split_path('/foo/Bar/x#f3?q3')
        self.assertEqual(path, '/foo/Bar/x')
        self.assertEqual(query, '')
        self.assertEqual(frag, 'f3?q3')

    def test_safe_uri(self):
        # positive
        self.assertTrue(proto.safe_uri('/foo/Bar/0'))
        self.assertTrue(proto.safe_uri('/foo/Bar.1'))
        self.assertTrue(proto.safe_uri('/foo/Bar-2'))
        self.assertTrue(proto.safe_uri('/foo/Bar+3'))
        self.assertTrue(proto.safe_uri('/foo/Bar_4'))
        self.assertTrue(proto.safe_uri('/foo/Bar!5'))
        self.assertTrue(proto.safe_uri('/foo/Bar$6'))
        self.assertTrue(proto.safe_uri('/foo/Bar&7'))
        self.assertTrue(proto.safe_uri('/foo/Bar\'8\''))
        self.assertTrue(proto.safe_uri('/foo/Bar(9)'))
        self.assertTrue(proto.safe_uri('/foo/Bar*1'))
        self.assertTrue(proto.safe_uri('/foo/Bar:1'))
        self.assertTrue(proto.safe_uri('/foo/Bar;1'))
        self.assertTrue(proto.safe_uri('/foo/Bar=1'))
        self.assertTrue(proto.safe_uri('/foo/Bar@1'))
        self.assertTrue(proto.safe_uri('/foo/Bar#Fans/0'))
        self.assertTrue(proto.safe_uri('/foo/Bar?only'))
        self.assertTrue(proto.safe_uri('/foo/Bar?1#2'))
        self.assertTrue(proto.safe_uri('/foo/Bar?select=X%20Y'))
        self.assertTrue(proto.safe_uri('/foo/Bar?select=X%2dY'))
        self.assertTrue(proto.safe_uri('/foo/Bar?select=X%bCY'))
        self.assertTrue(proto.safe_uri('/foo/Bar%201'))
        # negative
        self.assertFalse(proto.safe_uri('/foo/Bar 1'))
        self.assertFalse(proto.safe_uri('/foo/Bar<1>'))
        self.assertFalse(proto.safe_uri('/foo/Bar"1'))
        self.assertFalse(proto.safe_uri('/foo/Bar%1'))
        self.assertFalse(proto.safe_uri('/foo/Bar{1}'))
        self.assertFalse(proto.safe_uri('/foo/Bar|1'))
        self.assertFalse(proto.safe_uri('/foo/Bar\\1'))
        self.assertFalse(proto.safe_uri('/foo/Bar^1'))
        self.assertFalse(proto.safe_uri('/foo/Bar~1'))
        self.assertFalse(proto.safe_uri('/foo/Bar[1]'))
        self.assertFalse(proto.safe_uri('/foo/Bar`1'))
        self.assertFalse(proto.safe_uri('/foo/Bar#1#2'))
        self.assertFalse(proto.safe_uri('/foo/Bar#1?2'))
        self.assertFalse(proto.safe_uri('/foo/Bar?1?2'))
        self.assertFalse(proto.safe_uri('/foo/Bar%1'))
        self.assertFalse(proto.safe_uri('/foo/Bar?select=A%2'))
        self.assertFalse(proto.safe_uri('/foo/Bar?select=A%2GB'))

    def test_no_encoded_char_in_uri(self):
        # positive
        self.assertFalse(proto.encoded_char_in_uri('/foo/Bar%1'))
        self.assertFalse(proto.encoded_char_in_uri('/foo/Bar%1G'))
        self.assertFalse(proto.encoded_char_in_uri('/foo/Bar?q=X%20Y#x/y'))
        # negative
        self.assertTrue(proto.encoded_char_in_uri('/foo/Bar#a/x%20y'))
        self.assertTrue(proto.encoded_char_in_uri('/foo/Bar#a/x%BC0y'))
        self.assertTrue(proto.encoded_char_in_uri('/foo/Bar%1Ca#a/x/y'))
        self.assertTrue(proto.encoded_char_in_uri('/foo/Bar%B2#a/x/y'))
        self.assertTrue(proto.encoded_char_in_uri('/foo/Bar%aF#a/x/y'))

    def test_check_slash_redfish(self):
        response = mock.Mock(spec=requests.Response)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response.request = request
        # positive
        response.status_code = requests.codes.OK
        response.json.return_value = {"v1": "/redfish/v1/"}
        result, msg = proto.check_slash_redfish('/redfish', response)
        self.assertEqual(result, Result.PASS)
        self.assertIn('Test passed', msg)
        # negative
        response.status_code = requests.codes.NOT_FOUND
        response.json.return_value = None
        result, msg = proto.check_slash_redfish('/redfish', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('GET request to URI /redfish received status 404', msg)
        # negative
        response.status_code = requests.codes.OK
        response.json.return_value = {"v1": "/redfish/v1"}
        result, msg = proto.check_slash_redfish('/redfish', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('Content of /redfish resource contained ', msg)

    def test_response_is_json(self):
        response = mock.Mock(spec=requests.Response)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response.request = request
        # positive
        response.status_code = requests.codes.OK
        response.json.return_value = {"foo": "bar"}
        result, msg = proto.response_is_json('/redfish/v1/', response)
        self.assertEqual(result, Result.PASS)
        self.assertIn('Test passed', msg)
        # negative
        response.status_code = requests.codes.NOT_FOUND
        response.json.return_value = None
        result, msg = proto.response_is_json('/redfish/v1/', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('received status 404', msg)
        # negative
        response.status_code = requests.codes.OK
        response.json.side_effect = ValueError('Error parsing JSON')
        result, msg = proto.response_is_json('/redfish/v1/', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('did not return JSON response', msg)

    def test_response_is_xml(self):
        response = mock.Mock(spec=requests.Response)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response.request = request
        # positive
        response.status_code = requests.codes.OK
        response.text = '<Edmx><DataServices></DataServices></Edmx>'
        result, msg = proto.response_is_xml('/redfish/v1/$metadata', response)
        self.assertEqual(result, Result.PASS)
        self.assertIn('Test passed', msg)
        # negative
        response.status_code = requests.codes.NOT_FOUND
        response.text = None
        result, msg = proto.response_is_xml('/redfish/v1/$metadata', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('received status 404', msg)
        # negative
        response.status_code = requests.codes.OK
        response.text = '{"foo": "bar"}'
        result, msg = proto.response_is_xml('/redfish/v1/$metadata', response)
        self.assertEqual(result, Result.FAIL)
        self.assertIn('did not return XML response', msg)

    def test_relative_ref(self):
        # positive
        result, msg = proto.check_relative_ref('//localhost/redfish/v1')
        self.assertEqual(result, Result.PASS)
        result, msg = proto.check_relative_ref('//example.com/redfish/v1')
        self.assertEqual(result, Result.PASS)
        result, msg = proto.check_relative_ref('//127.0.0.1:8000/redfish/v1')
        self.assertEqual(result, Result.PASS)
        result, msg = proto.check_relative_ref('/redfish/v1')
        self.assertEqual(result, Result.PASS)
        # negative
        result, msg = proto.check_relative_ref('///example.com/redfish/v1')
        self.assertEqual(result, Result.FAIL)
        self.assertIn('should not start with a triple forward slash', msg)
        result, msg = proto.check_relative_ref('//localhost')
        self.assertEqual(result, Result.FAIL)
        self.assertIn('does not include the expected absolute-path', msg)
        result, msg = proto.check_relative_ref('//')
        self.assertEqual(result, Result.FAIL)
        self.assertIn('does not include the expected authority', msg)

    def test_response_content_type_is_json(self):
        response = mock.Mock(spec=requests.Response)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response.request = request
        response.headers = {
            'Content-Type': 'application/json'
        }
        r, msg = proto.response_content_type_is_json('/redfish/v1/foo',
                                                     response)
        self.assertEqual(r, Result.PASS)
        self.assertEqual('Test passed', msg)
        response.headers = {
            'Content-Type': 'application/JSON'
        }
        r, msg = proto.response_content_type_is_json('/redfish/v1/foo',
                                                     response)
        self.assertEqual(r, Result.PASS)
        self.assertEqual('Test passed', msg)
        response.headers = {
            'Content-Type': 'application/json; charset=utf-8'
        }
        r, msg = proto.response_content_type_is_json('/redfish/v1/foo',
                                                     response)
        self.assertEqual(r, Result.PASS)
        self.assertEqual('Test passed', msg)
        response.headers = {}
        r, msg = proto.response_content_type_is_json('/redfish/v1/foo',
                                                     response)
        self.assertEqual(r, Result.FAIL)
        self.assertIn('expected media type', msg)
        response.headers = {
            'Content-Type': 'application/xml'
        }
        r, msg = proto.response_content_type_is_json('/redfish/v1/foo',
                                                     response)
        self.assertEqual(r, Result.FAIL)
        self.assertIn('expected media type', msg)

    def test_check_etag_present(self):
        response = mock.Mock(spec=requests.Response)
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        response.request = request
        response.headers = {
            'ETag': '48305216'
        }
        r, msg = proto.check_etag_present('/redfish/v1/foo', response)
        self.assertEqual(r, Result.PASS)
        self.assertEqual('Test passed', msg)
        response.headers = {}
        r, msg = proto.check_etag_present('/redfish/v1/foo', response)
        self.assertEqual(r, Result.FAIL)
        self.assertIn('did not return an ETag', msg)

    def test_test_valid_etag_fail(self):
        uri = '/redfish/v1/foo'
        response = add_response(
            self.sut, uri, 'GET', status_code=requests.codes.OK,
            headers={'ETag': 'W/" 9573"'})  # space char not allowed
        proto.test_valid_etag(self.sut, uri, response)
        result = get_result(self.sut, Assertion.PROTO_ETAG_RFC7232,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Response from GET request to URI %s returned invalid '
                      'ETag header value' % uri, result['msg'])

    def test_test_valid_etag_pass(self):
        uri = '/redfish/v1/foo'
        response = add_response(
            self.sut, uri, 'GET', status_code=requests.codes.OK,
            headers={}, json={'@odata.etag': '"4A30/CF16"'})
        proto.test_valid_etag(self.sut, uri, response)
        result = get_result(self.sut, Assertion.PROTO_ETAG_RFC7232,
                            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_http_supported_methods_pass(self):
        proto.test_http_supported_methods(self.sut)
        result = get_result(self.sut, Assertion.PROTO_HTTP_SUPPORTED_METHODS,
                            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_http_supported_methods_fail(self):
        self._add_get_responses(status=requests.codes.NOT_FOUND)
        proto.test_http_supported_methods(self.sut)
        result = get_result(self.sut, Assertion.PROTO_HTTP_SUPPORTED_METHODS,
                            'GET', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('No GET requests had a successful response',
                      result['msg'])

    def test_test_http_unsupported_methods_pass(self):
        add_response(self.sut, '/redfish/v1/', 'TRACE',
                     requests.codes.METHOD_NOT_ALLOWED)
        proto.test_http_unsupported_methods(self.sut)
        result = get_result(self.sut, Assertion.PROTO_HTTP_UNSUPPORTED_METHODS,
                            'TRACE', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_http_unsupported_methods_fail(self):
        add_response(self.sut, '/redfish/v1/', 'TRACE',
                     requests.codes.BAD_REQUEST)
        proto.test_http_unsupported_methods(self.sut)
        result = get_result(self.sut, Assertion.PROTO_HTTP_UNSUPPORTED_METHODS,
                            'TRACE', '/redfish/v1/')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('TRACE method returned status', result['msg'])

    def test_test_protocol_details_cover(self):
        proto.test_protocol_details(self.sut)


if __name__ == '__main__':
    unittest.main()
