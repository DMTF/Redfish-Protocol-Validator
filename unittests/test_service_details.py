# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from assertions import service_details as service
from assertions.constants import Assertion, RequestType, Result, SSDP_ALL
from assertions.constants import SSDP_REDFISH
from assertions.system_under_test import SystemUnderTest
from unittests.utils import add_response, get_result


class ServiceDetails(TestCase):

    def setUp(self):
        super(ServiceDetails, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        self.mock_session = mock.MagicMock(spec=requests.Session)
        self.sut._set_session(self.mock_session)
        self.uuid = '92384634-2938-2342-8820-489239905423'
        self.subscriptions_uri = '/redfish/v1/EventService/Subscriptions'
        self.sse_uri = '/redfish/v1/EventService/SSE'

    def test_test_event_service_subscription_not_tested(self):
        service.test_event_service_subscription(self.sut)
        result = get_result(self.sut, Assertion.SERV_EVENT_POST_RESP, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No event subscriptions URI found', result['msg'])

    def test_test_event_service_subscription_fail1(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.OK)
        self.mock_session.post.return_value = post_resp
        service.test_event_service_subscription(self.sut)
        result = get_result(self.sut, Assertion.SERV_EVENT_POST_RESP, 'POST',
                            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status code 200; expected 201', result['msg'])

    def test_test_event_service_subscription_fail2(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.CREATED, headers={})
        self.mock_session.post.return_value = post_resp
        service.test_event_service_subscription(self.sut)
        result = get_result(self.sut, Assertion.SERV_EVENT_POST_RESP, 'POST',
                            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('POST request to %s did not include a Location header' %
                      self.subscriptions_uri, result['msg'])

    def test_test_event_service_subscription_pass(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        uri = self.subscriptions_uri + '/1'
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.CREATED, headers={'Location': uri})
        self.mock_session.post.return_value = post_resp
        service.test_event_service_subscription(self.sut)
        result = get_result(self.sut, Assertion.SERV_EVENT_POST_RESP, 'POST',
                            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.mock_session.delete.called_once_with(self.sut.rhost + uri)

    def test_test_event_error_on_bad_request_not_tested(self):
        service.test_event_error_on_bad_request(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No event subscriptions URI found', result['msg'])

    def test_test_event_error_on_bad_request_fail(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        uri = self.subscriptions_uri + '/1'
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.CREATED, headers={'Location': uri})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_bad_request(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status code 201; expected 400', result['msg'])

    def test_test_event_error_on_bad_request_warn(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.UNAUTHORIZED, headers={})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_bad_request(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('returned status code 401; expected 400', result['msg'])

    def test_test_event_error_on_bad_request_pass(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.BAD_REQUEST, headers={})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_bad_request(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_event_error_on_mutually_excl_props_not_tested(self):
        service.test_event_error_on_mutually_excl_props(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No event subscriptions URI found', result['msg'])

    def test_test_event_error_on_mutually_excl_props_fail(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        uri = self.subscriptions_uri + '/1'
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.CREATED, headers={'Location': uri})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_mutually_excl_props(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('returned status code 201; expected 400', result['msg'])

    def test_test_event_error_on_mutually_excl_props_warn(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.UNAUTHORIZED, headers={})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_mutually_excl_props(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.WARN, result['result'])
        self.assertIn('returned status code 401; expected 400', result['msg'])

    def test_test_event_error_on_mutually_excl_props_pass(self):
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        post_resp = add_response(
            self.sut, self.subscriptions_uri, 'POST',
            status_code=requests.codes.BAD_REQUEST, headers={})
        self.mock_session.post.return_value = post_resp
        service.test_event_error_on_mutually_excl_props(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, 'POST',
            self.subscriptions_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    @mock.patch('assertions.service_details.utils.discover_ssdp')
    def test_pre_ssdp(self, mock_discover_ssdp):
        self.sut.set_mgr_net_proto_uri(
            '/redfish/v1/Managers/BMC/NetworkProtocol')
        self.mock_session.get.return_value.ok = True
        self.mock_session.get.return_value.status_code = requests.codes.OK
        self.mock_session.get.return_value.json.return_value = {
            'SSDP': {'ProtocolEnabled': True}
        }
        service.pre_ssdp(self.sut)
        self.assertEqual(True, self.sut.ssdp_enabled)

    def test_test_ssdp_can_be_disabled_not_tested1(self):
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root', result['msg'])

    def test_test_ssdp_can_be_disabled_not_tested2(self):
        other_uuid = '92384634-2938-2342-8820-489876543210'
        self.sut.set_service_uuid(self.uuid)
        services = {
            other_uuid: {'USN': 'uuid:%s' % other_uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP', result['msg'])

    def test_test_ssdp_can_be_disabled_not_tested3(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('ManagerNetworkProtocol URL not found', result['msg'])

    def test_test_ssdp_can_be_disabled_not_tested4(self):
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_mgr_net_proto_uri(
            '/redfish/v1/Managers/BMC/NetworkProtocol')
        self.mock_session.get.return_value.ok = True
        self.mock_session.get.return_value.status_code = requests.codes.OK
        self.mock_session.get.return_value.json.return_value = {
            'SSDP': {'ProtocolEnabled': False}
        }
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('SSDP does not appear to be enabled',
                      result['msg'])

    def test_test_ssdp_can_be_disabled_fail1(self):
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_mgr_net_proto_uri(
            '/redfish/v1/Managers/BMC/NetworkProtocol')
        add_response(self.sut, self.sut.mgr_net_proto_uri, 'GET',
                     status_code=requests.codes.OK)
        self.sut.set_ssdp_enabled(True)
        self.mock_session.patch.return_value.ok = False
        self.mock_session.patch.return_value.status_code = requests.codes.BAD
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            'PATCH', self.sut.mgr_net_proto_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Attempt to disable SSDP failed',
                      result['msg'])

    @mock.patch('assertions.service_details.utils.discover_ssdp')
    def test_test_ssdp_can_be_disabled_fail2(self, mock_discover_ssdp):
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        mock_discover_ssdp.return_value = services
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_mgr_net_proto_uri(
            '/redfish/v1/Managers/BMC/NetworkProtocol')
        add_response(self.sut, self.sut.mgr_net_proto_uri, 'GET',
                     status_code=requests.codes.OK)
        self.sut.set_ssdp_enabled(True)
        self.mock_session.patch.return_value.ok = True
        self.mock_session.patch.return_value.status_code = requests.codes.OK
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            'PATCH', self.sut.mgr_net_proto_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Service responded to SSDP query after disabling SSDP',
                      result['msg'])

    @mock.patch('assertions.service_details.utils.discover_ssdp')
    def test_test_ssdp_can_be_disabled_pass(self, mock_discover_ssdp):
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        mock_discover_ssdp.return_value = {}
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_mgr_net_proto_uri(
            '/redfish/v1/Managers/BMC/NetworkProtocol')
        add_response(self.sut, self.sut.mgr_net_proto_uri, 'GET',
                     status_code=requests.codes.OK,
                     headers={'ETag': 'abc'})
        self.sut.set_ssdp_enabled(True)
        self.mock_session.patch.return_value.ok = True
        self.mock_session.patch.return_value.status_code = requests.codes.OK
        self.mock_session.patch.return_value.headers = {'ETag': 'def'}
        service.test_ssdp_can_be_disabled(self.sut)
        result = get_result(self.sut, Assertion.SERV_SSDP_CAN_BE_DISABLED,
                            'PATCH', self.sut.mgr_net_proto_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])
        self.assertEqual(self.mock_session.patch.call_count, 2)
        # expected call to disable SSDP
        self.mock_session.patch.assert_any_call(
            self.sut.rhost + self.sut.mgr_net_proto_uri,
            json={'SSDP': {'ProtocolEnabled': False}},
            headers={'If-Match': 'abc'})
        # expected call to re-enable SSDP
        self.mock_session.patch.assert_called_with(
            self.sut.rhost + self.sut.mgr_net_proto_uri,
            json={'SSDP': {'ProtocolEnabled': True}},
            headers={'If-Match': 'def'})

    def test_test_ssdp_usn_matches_service_root_uuid_not_tested1(self):
        service.test_ssdp_usn_matches_service_root_uuid(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_usn_matches_service_root_uuid_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_usn_matches_service_root_uuid(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No SSDP responses found matching',
                      result['msg'])

    def test_test_ssdp_usn_matches_service_root_uuid_warn(self):
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_ssdp_enabled(True)
        usn = 'uuid:%s' % '123-456'
        services = {
            '123-456': {
                'ST': 'urn:dmtf-org:service:redfish-rest:1',
                'USN': usn,
                'AL': self.sut.rhost + '/redfish/v1/'
            },
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_usn_matches_service_root_uuid(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                            '', usn)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('No SSDP response was found for Service Root UUID %s, '
                      'but a response was found for UUID %s' % (
                       self.uuid, '123-456'), result['msg'])

    def test_test_ssdp_usn_matches_service_root_uuid_pass(self):
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_ssdp_enabled(True)
        services = {
            '123-456': {'USN': 'uuid:%s' % '123-456'},
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_usn_matches_service_root_uuid(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                            '', 'uuid:%s' % self.uuid)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_ssdp_uuid_in_canonical_format_not_tested1(self):
        service.test_ssdp_uuid_in_canonical_format(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_uuid_in_canonical_format_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_uuid_in_canonical_format(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT,
                            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP',
                      result['msg'])

    def test_test_ssdp_uuid_in_canonical_format_fail(self):
        self.sut.set_service_uuid(self.uuid)
        usn = 'uuid:%s:service:redfish-rest:1' % self.uuid
        services = {
            self.uuid: {'USN': usn}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_uuid_in_canonical_format(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT,
                            '', usn)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The unique ID found (%s) does not match the regex '
                      'pattern' % usn,
                      result['msg'])

    def test_test_ssdp_uuid_in_canonical_format_pass(self):
        self.sut.set_service_uuid(self.uuid)
        usn = 'uuid:%s::urn:dmtf-org:service:redfish-rest:1' % self.uuid
        services = {
            self.uuid: {'USN': usn}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_uuid_in_canonical_format(self.sut)
        result = get_result(self.sut,
                            Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT,
                            '', usn)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_ssdp_msearch_responds_to_redfish_or_all_not_tested1(self):
        service.test_ssdp_msearch_responds_to_redfish_or_all(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_msearch_responds_to_redfish_or_all_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_msearch_responds_to_redfish_or_all(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP',
                      result['msg'])

    def test_test_ssdp_msearch_responds_to_redfish_or_all_fail1(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_msearch_responds_to_redfish_or_all(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('not found for ST of ssdp:all',
                      result['msg'])

    def test_test_ssdp_msearch_responds_to_redfish_or_all_fail2(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_ALL, services)
        service.test_ssdp_msearch_responds_to_redfish_or_all(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('not found for ST of the Redfish Service',
                      result['msg'])

    def test_test_ssdp_msearch_responds_to_redfish_or_all_pass(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {'USN': 'uuid:%s' % self.uuid}
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        self.sut.add_ssdp_services(SSDP_ALL, services)
        service.test_ssdp_msearch_responds_to_redfish_or_all(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_ssdp_st_header_format_not_tested1(self):
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_st_header_format_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP',
                      result['msg'])

    def test_test_ssdp_st_header_format_fail1(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                'USN': 'abc'
                # no ST header
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('ST header not found in M-SEARCH response',
                      result['msg'])

    def test_test_ssdp_st_header_format_fail2(self):
        self.sut.set_service_uuid(self.uuid)
        st = 'urn:dmtf-org:service::1'  # invalid (missing 'redfish-rest')
        services = {
            self.uuid: {
                'USN': 'abc',
                'ST': st
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', st)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Returned ST header "%s" does not match the regex' % st,
                      result['msg'])

    def test_test_ssdp_st_header_format_fail3(self):
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_version('1.6.0')
        st = 'urn:dmtf-org:service:redfish-rest:1'  # missing minor version
        services = {
            self.uuid: {
                'USN': 'abc',
                'ST': st
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', st)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('6, but the minor version in the ST header is missing',
                      result['msg'])

    def test_test_ssdp_st_header_format_fail4(self):
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_version('1.6.0')
        st = 'urn:dmtf-org:service:redfish-rest:1:5'  # minor version mismatch
        services = {
            self.uuid: {
                'USN': 'abc',
                'ST': st
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', st)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('6, but the minor version in the ST header is 5',
                      result['msg'])

    def test_test_ssdp_st_header_format_pass(self):
        self.sut.set_service_uuid(self.uuid)
        self.sut.set_version('1.6.0')
        st = 'urn:dmtf-org:service:redfish-rest:1:6'  # correct minor version
        services = {
            self.uuid: {
                'USN': 'abc',
                'ST': st
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_st_header_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_ST_HEADER_FORMAT,
            '', st)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_ssdp_al_header_points_to_service_root_not_tested1(self):
        service.test_ssdp_al_header_points_to_service_root(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_al_header_points_to_service_root_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_al_header_points_to_service_root(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP',
                      result['msg'])

    def test_test_ssdp_al_header_points_to_service_root_fail1(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                'USN': 'abc'
                # no AL header
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_al_header_points_to_service_root(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('AL header not found in M-SEARCH response',
                      result['msg'])

    def test_test_ssdp_al_header_points_to_service_root_fail2(self):
        self.sut.set_service_uuid(self.uuid)
        # AL header with bad service root path
        al = self.sut.rhost + '/redfish/foo'
        services = {
            self.uuid: {
                'USN': 'abc',
                'AL': al
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_al_header_points_to_service_root(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
            '', al)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('AL header "%s" does appear to be a Service Root URL'
                      % al, result['msg'])

    def test_test_ssdp_al_header_points_to_service_root_pass(self):
        self.sut.set_service_uuid(self.uuid)
        # good AL header
        al = self.sut.rhost + '/redfish/v1/'
        services = {
            self.uuid: {
                'USN': 'abc',
                'AL': al
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_al_header_points_to_service_root(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
            '', al)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_ssdp_m_search_response_format_not_tested1(self):
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service UUID not found in Service Root',
                      result['msg'])

    def test_test_ssdp_m_search_response_format_not_tested2(self):
        self.sut.set_service_uuid(self.uuid)
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Service not found via SSDP',
                      result['msg'])

    def test_test_ssdp_m_search_response_format_fail1(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                'ST': 'abc',
                'USN': 'def',
                'AL': 'hij'
                # missing CACHE-CONTROL
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more errors found with M-SEARCH response',
                      result['msg'])
        self.assertIn('No CACHE-CONTROL header found',
                      result['msg'])

    def test_test_ssdp_m_search_response_format_fail2(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                'ST': 'abc',
                'USN': 'def',
                'AL': 'hij',
                # CACHE-CONTROL max-age too short
                'CACHE-CONTROL': 'max-age=120'
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more errors found with M-SEARCH response',
                      result['msg'])
        self.assertIn('CACHE-CONTROL header is "%s"; expected' % 'max-age=120',
                      result['msg'])

    def test_test_ssdp_m_search_response_format_fail3(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                # all expected headers missing
                'FOO': 'foo'
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more errors found with M-SEARCH response',
                      result['msg'])
        self.assertIn('No CACHE-CONTROL header found',
                      result['msg'])
        self.assertIn('No ST header found',
                      result['msg'])
        self.assertIn('No USN header found',
                      result['msg'])
        self.assertIn('No AL header found',
                      result['msg'])

    def test_test_ssdp_m_search_response_format_pass(self):
        self.sut.set_service_uuid(self.uuid)
        services = {
            self.uuid: {
                'ST': 'abc',
                'USN': 'def',
                'AL': 'hij',
                'CACHE-CONTROL': 'max-age=1800'
            }
        }
        self.sut.add_ssdp_services(SSDP_REDFISH, services)
        service.test_ssdp_m_search_response_format(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_successful_response_not_tested1(self):
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEventUri available',
                      result['msg'])

    def test_test_sse_successful_response_not_tested2(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = mock.MagicMock(spec=requests.Response)
        get_resp.status_code = requests.codes.BAD_REQUEST
        get_resp.ok = False
        request = mock.Mock(spec=requests.Request)
        request.method = 'GET'
        self.mock_session.get.return_value = get_resp
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response from GET request to URL %s was not successful'
                      % self.sse_uri, result['msg'])

    @mock.patch('assertions.utils.logging.warning')
    def test_test_sse_successful_response_exception(self, mock_warn):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.mock_session.get.side_effect = ConnectionError
        service.test_sse_successful_response(self.sut)
        args = mock_warn.call_args[0]
        self.assertIn('Caught ConnectionError while opening SSE',
                      args[0])

    def test_test_sse_successful_response_fail1(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.ACCEPTED,
                                headers={'Content-Type': 'text/event-stream'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('request to URL %s succeeded with status %s' %
                      (self.sse_uri, requests.codes.ACCEPTED), result['msg'])
        self.assertIn('expected status %s' % requests.codes.OK,
                      result['msg'])

    def test_test_sse_successful_response_fail2(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.OK,
                                headers={'Content-Type': 'text/html'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Content-Type header in response from GET request to '
                      'URL %s was %s' % (self.sse_uri, 'text/html'),
                      result['msg'])
        self.assertIn('expected %s or %s' %
                      ('text/event-stream', 'text/event-stream;charset=utf-8'),
                      result['msg'])

    def test_test_sse_successful_response_fail3(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.OK,
                                headers={})
        self.mock_session.get.return_value = get_resp
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('No Content-Type header in response from GET request to '
                      'URL %s' % self.sse_uri, result['msg'])

    def test_test_sse_successful_response_pass(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.OK,
                                headers={'Content-Type': 'text/event-stream'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_successful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_SUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_unsuccessful_response_not_tested1(self):
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEventUri available',
                      result['msg'])

    def test_test_sse_unsuccessful_response_not_tested2(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.OK)
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Response from GET request to URL %s was successful'
                      % self.sse_uri, result['msg'])

    def test_test_sse_unsuccessful_response_fail1(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE, headers={})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('No Content-Type header in response', result['msg'])

    def test_test_sse_unsuccessful_response_fail2(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE,
                                headers={'Content-Type': 'text/html'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Content-Type header in response from GET request to '
                      'URL %s was %s' % (self.sse_uri, 'text/html'),
                      result['msg'])

    def test_test_sse_unsuccessful_response_fail3(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        body = {
            'error': 'Base.1.0.GeneralError'
        }
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE, json=body,
                                headers={'Content-Type': 'application/json'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more problems found with error response:',
                      result['msg'])
        self.assertIn('Property "error" is missing from response body or is '
                      'not a complex property', result['msg'])

    def test_test_sse_unsuccessful_response_fail4(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        body = {
            'error': {
            }
        }
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE, json=body,
                                headers={'Content-Type': 'application/json'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more problems found with error response:',
                      result['msg'])
        self.assertIn('Property "code" missing from "error" complex property',
                      result['msg'])
        self.assertIn('Property "message" missing from "error" complex '
                      'property', result['msg'])
        self.assertIn('Property "@Message.ExtendedInfo" missing from "error" '
                      'complex property', result['msg'])

    def test_test_sse_unsuccessful_response_fail5(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        body = {
            'error': {
                'code': 200,
                'message': True,
                '@Message.ExtendedInfo': {}
            }
        }
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE, json=body,
                                headers={'Content-Type': 'application/json'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('One or more problems found with error response:',
                      result['msg'])
        self.assertIn('Property "code" is not a string', result['msg'])
        self.assertIn('Property "message" is not a string', result['msg'])
        self.assertIn('Property "@Message.ExtendedInfo" is not a list',
                      result['msg'])

    def test_test_sse_unsuccessful_response_exception(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.mock_session.get.side_effect = ConnectionError
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Caught ConnectionError while opening SSE',
                      result['msg'])

    def test_test_sse_unsuccessful_response_pass(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        body = {
            'error': {
                'code': 'Base.1.0.GeneralError',
                'message': 'A general error has occurred.',
                '@Message.ExtendedInfo': [
                    {}
                ]
            }
        }
        get_resp = add_response(self.sut, self.sse_uri, 'GET',
                                requests.codes.NOT_ACCEPTABLE, json=body,
                                headers={'Content-Type': 'application/json'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_unsuccessful_response(self.sut)
        result = get_result(
            self.sut, Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE,
            'GET', self.sse_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_blank_lines_between_events_not_tested1(self):
        service.test_sse_blank_lines_between_events(self.sut, None)
        result = get_result(
            self.sut, Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent stream opened',
                      result['msg'])

    def test_test_sse_blank_lines_between_events_not_tested2(self):
        sse_response = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n'
        ]
        events = service.read_sse_events(sse_response)
        service.test_sse_blank_lines_between_events(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    @mock.patch('assertions.utils.time.time')
    def test_test_sse_blank_lines_between_events_timeout(self, mock_time):
        sse_response = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b'id:210\ndata:{"id": "210"}\n\n'
        ]
        # mock 7 seconds elapsed
        mock_time.side_effect = [1000, 1000, 1007, 1007]
        events = service.read_sse_events(sse_response)
        service.test_sse_blank_lines_between_events(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_blank_lines_between_events_fail(self):
        sse_response = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b'id:210\ndata:{"id": "210"}\n',  # blank line missing
            b'id:211\ndata:{"id": "211"}\n',
        ]
        events = service.read_sse_events(sse_response)
        service.test_sse_blank_lines_between_events(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Blank line not found between events',
                      result['msg'])

    def test_test_sse_blank_lines_between_events_pass(self):
        sse_response = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n',
            b'id:210\ndata:{"id": "210"}\n\n',  # blank line present
            b'id:211\ndata:{"id": "211"}\n\n',
        ]
        events = service.read_sse_events(sse_response)
        service.test_sse_blank_lines_between_events(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_connection_open_until_closed_not_tested(self):
        service.test_sse_connection_open_until_closed(self.sut, None)
        result = get_result(
            self.sut, Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent stream opened',
                      result['msg'])

    def test_test_sse_connection_open_until_closed_fail(self):
        sse_response = mock.MagicMock(spec=requests.Response)
        sse_response.__iter__.return_value = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n'
        ]
        service.test_sse_connection_open_until_closed(self.sut, sse_response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('SSE stream, connection appears to still be open',
                      result['msg'])

    def test_test_sse_connection_open_until_closed_pass(self):
        sse_response = mock.MagicMock(spec=requests.Response)
        sse_response.__iter__.return_value = []
        service.test_sse_connection_open_until_closed(self.sut, sse_response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_event_dest_deleted_on_close_not_tested1(self):
        service.test_sse_event_dest_deleted_on_close(self.sut, None)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent stream opened',
                      result['msg'])

    def test_test_sse_event_dest_deleted_on_close_not_tested2(self):
        response = mock.Mock()
        service.test_sse_event_dest_deleted_on_close(self.sut, response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No EventDestination URI found',
                      result['msg'])

    @mock.patch('assertions.service_details.time.sleep')
    def test_test_sse_event_dest_deleted_on_close_not_tested3(
            self, mock_sleep):
        response = mock.Mock()
        uri = self.subscriptions_uri + '/1'
        self.sut.set_event_dest_uri(uri)
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.UNAUTHORIZED)
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_deleted_on_close(self.sut, response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Unexpected status on GET to EventDestination resource',
                      result['msg'])

    @mock.patch('assertions.service_details.time.sleep')
    def test_test_sse_event_dest_deleted_on_close_fail(
            self, mock_sleep):
        response = mock.Mock()
        uri = self.subscriptions_uri + '/1'
        self.sut.set_event_dest_uri(uri)
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.OK)
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_deleted_on_close(self.sut, response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('EventDestination resource not deleted',
                      result['msg'])

    @mock.patch('assertions.service_details.time.sleep')
    def test_test_sse_event_dest_deleted_on_close_pass(
            self, mock_sleep):
        response = mock.Mock()
        uri = self.subscriptions_uri + '/1'
        self.sut.set_event_dest_uri(uri)
        get_resp1 = add_response(self.sut, uri, 'GET',
                                 status_code=requests.codes.OK)
        get_resp2 = add_response(self.sut, uri, 'GET',
                                 status_code=requests.codes.NOT_FOUND)
        self.mock_session.get.side_effect = [get_resp1, get_resp1, get_resp2]
        service.test_sse_event_dest_deleted_on_close(self.sut, response)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_events_sent_via_open_connection_not_tested1(self):
        service.test_sse_events_sent_via_open_connection(self.sut, None)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_events_sent_via_open_connection_not_tested2(self):
        service.test_sse_events_sent_via_open_connection(self.sut, [])
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_events_sent_via_open_connection_pass(self):
        event = mock.Mock()
        service.test_sse_events_sent_via_open_connection(self.sut, event)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_open_creates_event_dest_not_tested1(self):
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertIsNone(r)
        self.assertIsNone(e)
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEventUri available',
                      result['msg'])

    def test_test_sse_open_creates_event_dest_not_tested2(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertIsNone(r)
        self.assertIsNone(e)
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No EventService Subscriptions URI available',
                      result['msg'])

    def test_test_sse_open_creates_event_dest_not_tested3(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        get_resp1 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK)
        get_resp2 = add_response(self.sut, self.sut.server_sent_event_uri,
                                 'GET', status_code=requests.codes.NOT_FOUND,
                                 request_type=RequestType.STREAMING)
        self.mock_session.get.side_effect = [get_resp1, get_resp2]
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertIsNone(r)
        self.assertIsNone(e)
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            'GET', self.sut.server_sent_event_uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Open of SSE stream failed',
                      result['msg'])

    def test_test_sse_open_creates_event_dest_not_tested4(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        get_resp1 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': []})
        get_resp2 = add_response(self.sut, self.sut.server_sent_event_uri,
                                 'GET', status_code=requests.codes.OK,
                                 request_type=RequestType.STREAMING)
        get_resp3 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': [
                                     {'@odata.id': '/foo'},
                                     {'@odata.id': '/bar'}
                                 ]})
        self.mock_session.get.side_effect = [get_resp1, get_resp2, get_resp3]
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertIsNone(r)
        self.assertIsNone(e)
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Unable to locate a new EventDestination resource',
                      result['msg'])

    def test_test_sse_open_creates_event_dest_fail(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        get_resp1 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': []})
        get_resp2 = add_response(self.sut, self.sut.server_sent_event_uri,
                                 'GET', status_code=requests.codes.OK,
                                 request_type=RequestType.STREAMING)
        get_resp3 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': []})
        self.mock_session.get.side_effect = [get_resp1, get_resp2, get_resp3]
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertIsNone(r)
        self.assertIsNone(e)
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Unable to locate a new EventDestination resource',
                      result['msg'])

    def test_test_sse_open_creates_event_dest_pass(self):
        self.sut.set_server_sent_event_uri(self.sse_uri)
        self.sut.set_nav_prop_uri('Subscriptions', self.subscriptions_uri)
        get_resp1 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': []})
        get_resp2 = add_response(self.sut, self.sut.server_sent_event_uri,
                                 'GET', status_code=requests.codes.OK,
                                 request_type=RequestType.STREAMING)
        get_resp3 = add_response(self.sut, self.sut.subscriptions_uri, 'GET',
                                 status_code=requests.codes.OK,
                                 json={'Members': [{'@odata.id': '/foo'}]})
        self.mock_session.get.side_effect = [get_resp1, get_resp2, get_resp3]
        r, e = service.test_sse_open_creates_event_dest(self.sut)
        self.assertEqual(r, get_resp2)
        self.assertEqual(e, '/foo')
        result = get_result(
            self.sut, Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
            '', e)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_close_connection_if_event_dest_deleted_not_tested1(self):
        service.test_sse_close_connection_if_event_dest_deleted(
            self.sut, None, '/foo')
        result = get_result(
            self.sut,
            Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent stream opened',
                      result['msg'])

    def test_test_sse_close_connection_if_event_dest_deleted_not_tested2(self):
        service.test_sse_close_connection_if_event_dest_deleted(
            self.sut, mock.Mock(), None)
        result = get_result(
            self.sut,
            Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No EventDestination resource found',
                      result['msg'])

    def test_test_sse_close_connection_if_event_dest_deleted_fail1(self):
        event_dest = '/redfish/v1/EventService/Subscriptions/1'
        del_resp = add_response(self.sut, event_dest, 'DELETE',
                                status_code=requests.codes.UNAUTHORIZED)
        self.mock_session.delete.return_value = del_resp
        service.test_sse_close_connection_if_event_dest_deleted(
            self.sut, mock.Mock(), event_dest)
        result = get_result(
            self.sut,
            Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
            'DELETE', event_dest)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Delete of EventDestination resource %s failed' %
                      event_dest, result['msg'])

    @mock.patch('assertions.service_details.time.sleep')
    def test_test_sse_close_connection_if_event_dest_deleted_fail2(
            self, mock_sleep):
        event_dest = '/redfish/v1/EventService/Subscriptions/1'
        del_resp = add_response(self.sut, event_dest, 'DELETE',
                                status_code=requests.codes.OK)
        self.mock_session.delete.return_value = del_resp
        sse_response = mock.MagicMock(spec=requests.Response)
        sse_response.__iter__.return_value = [
            b': stream keep-alive\n\n',
            b': stream keep-alive\n\n'
        ]
        service.test_sse_close_connection_if_event_dest_deleted(
            self.sut, sse_response, event_dest)
        result = get_result(
            self.sut,
            Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
            'DELETE', event_dest)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('resource, the connection appears to still be open',
                      result['msg'])

    @mock.patch('assertions.service_details.time.sleep')
    def test_test_sse_close_connection_if_event_dest_deleted_pass(
            self, mock_sleep):
        event_dest = '/redfish/v1/EventService/Subscriptions/1'
        del_resp = add_response(self.sut, event_dest, 'DELETE',
                                status_code=requests.codes.OK)
        self.mock_session.delete.return_value = del_resp
        sse_response = mock.MagicMock(spec=requests.Response)
        sse_response.__iter__.return_value = []
        service.test_sse_close_connection_if_event_dest_deleted(
            self.sut, sse_response, event_dest)
        result = get_result(
            self.sut,
            Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
            'DELETE', event_dest)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_event_dest_context_opaque_str_not_tested1(self):
        service.test_sse_event_dest_context_opaque_str(self.sut, None)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR, '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No EventDestination URI found',
                      result['msg'])

    def test_test_sse_event_dest_context_opaque_str_not_tested2(self):
        uri = '/redfish/v1/EventService/Subscriptions/1'
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.NOT_FOUND)
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_context_opaque_str(self.sut, uri)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('Failed to read the EventDestination URI',
                      result['msg'])

    def test_test_sse_event_dest_context_opaque_str_fail1(self):
        uri = '/redfish/v1/EventService/Subscriptions/1'
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.OK,
                                json={})
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_context_opaque_str(self.sut, uri)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('The required property Context was missing',
                      result['msg'])

    def test_test_sse_event_dest_context_opaque_str_fail2(self):
        uri = '/redfish/v1/EventService/Subscriptions/1'
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.OK,
                                json={'Context': None})
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_context_opaque_str(self.sut, uri)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Context property from the EventDestination resource',
                      result['msg'])
        self.assertIn('(value: None)',
                      result['msg'])

    def test_test_sse_event_dest_context_opaque_str_pass(self):
        uri = '/redfish/v1/EventService/Subscriptions/1'
        get_resp = add_response(self.sut, uri, 'GET',
                                status_code=requests.codes.OK,
                                json={'Context': 'abcdef-012345'})
        self.mock_session.get.return_value = get_resp
        service.test_sse_event_dest_context_opaque_str(self.sut, uri)
        result = get_result(
            self.sut, Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR,
            'GET', uri)
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_id_uniquely_identifies_payload_not_tested(self):
        service.test_sse_id_uniquely_identifies_payload(self.sut, [])
        result = get_result(
            self.sut, Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_id_uniquely_identifies_payload_fail1(self):
        e1 = mock.Mock()
        e1.data = mock.Mock()
        e1.id = None
        e2 = mock.Mock()
        e2.data = mock.Mock()
        e2.id = ''
        e3 = mock.Mock()
        e3.data = mock.Mock()
        e3.id = '123'
        events = [e1, e2, e3]
        service.test_sse_id_uniquely_identifies_payload(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('2 out of 3 event payloads did not have an id field',
                      result['msg'])

    def test_test_sse_id_uniquely_identifies_payload_fail2(self):
        e1 = mock.Mock()
        e1.data = mock.Mock()
        e1.id = '123'
        e2 = mock.Mock()
        e2.data = mock.Mock()
        e2.id = '456'
        e3 = mock.Mock()
        e3.data = mock.Mock()
        e3.id = '123'
        events = [e1, e2, e3]
        service.test_sse_id_uniquely_identifies_payload(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('More than one event used the same id field',
                      result['msg'])

    def test_test_sse_id_uniquely_identifies_payload_pass(self):
        e1 = mock.Mock()
        e1.data = mock.Mock()
        e1.id = '123'
        e2 = mock.Mock()
        e2.data = mock.Mock()
        e2.id = '456'
        e3 = mock.Mock()
        e3.data = mock.Mock()
        e3.id = '789'
        events = [e1, e2, e3]
        service.test_sse_id_uniquely_identifies_payload(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_data_based_on_payload_format_not_tested(self):
        service.test_sse_data_based_on_payload_format(self.sut, [])
        result = get_result(
            self.sut, Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_data_based_on_payload_format_fail(self):
        e1 = mock.Mock()
        e1.data = '{"@odata.type": "#Event.v1_1_0.Event","Id": "123"}'
        e1.id = '123'
        e2 = mock.Mock()
        e2.data = '{"@odata.type": "#MetricReport.MetricReport","Id": "456"}'
        e2.id = '456'
        e3 = mock.Mock()
        e3.data = '{"@odata.type": "#MyEvent.v1_1_0.MyEvent","Id": "789"}'
        e3.id = '789'
        events = [e1, e2, e3]
        service.test_sse_data_based_on_payload_format(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('Event %s had payload format %s; expected %s or %s' %
                      (e3.id, 'MyEvent', 'Event', 'MetricReport'),
                      result['msg'])

    def test_test_sse_data_based_on_payload_format_pass(self):
        e1 = mock.Mock()
        e1.data = '{"@odata.type": "#Event.v1_1_0.Event","Id": "123"}'
        e1.id = '123'
        e2 = mock.Mock()
        e2.data = '{"@odata.type": "#MetricReport.MetricReport","Id": "456"}'
        e2.id = '456'
        e3 = mock.Mock()
        e3.data = ''
        e3.id = '789'
        events = [e1, e2, e3]
        service.test_sse_data_based_on_payload_format(self.sut, events)
        result = get_result(
            self.sut, Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_json_event_message_format_not_tested1(self):
        service.test_sse_json_event_message_format(self.sut, [])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_json_event_message_format_not_tested2(self):
        e = mock.Mock()
        e.data = '{"@odata.type": "#MetricReport.MetricReport","Id": "456"}'
        e.id = '456'
        service.test_sse_json_event_message_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No Event object payload found',
                      result['msg'])

    def test_test_sse_json_event_message_format_fail(self):
        e = mock.Mock()
        # JSON error: missing curly braces
        e.data = '"@odata.type": "#Event.v1_1_0.Event","Id": "456"'
        e.id = '456'
        service.test_sse_json_event_message_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('JSON decode error of Event payload for event %s' %
                      '456', result['msg'])

    def test_test_sse_json_event_message_format_pass(self):
        e = mock.Mock()
        e.data = '{"@odata.type": "#Event.v1_1_0.Event","Id": "456"}'
        e.id = '456'
        service.test_sse_json_event_message_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    def test_test_sse_json_metric_report_format_not_tested1(self):
        service.test_sse_json_metric_report_format(self.sut, [])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No ServerSentEvent events read',
                      result['msg'])

    def test_test_sse_json_metric_report_format_not_tested2(self):
        e = mock.Mock()
        e.data = '{"@odata.type": "#Event.v1_1_0.Event","Id": "456"}'
        e.id = '456'
        service.test_sse_json_metric_report_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.NOT_TESTED, result['result'])
        self.assertIn('No MetricReport object payload found',
                      result['msg'])

    def test_test_sse_json_metric_report_format_fail(self):
        e = mock.Mock()
        # JSON error: missing curly braces
        e.data = '"@odata.type": "#MetricReport.MetricReport","Id": "456"'
        e.id = '456'
        service.test_sse_json_metric_report_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.FAIL, result['result'])
        self.assertIn('JSON decode error of MetricReport payload for event %s'
                      % '456', result['msg'])

    def test_test_sse_json_metric_report_format_pass(self):
        e = mock.Mock()
        e.data = '{"@odata.type": "#MetricReport.MetricReport","Id": "456"}'
        e.id = '456'
        service.test_sse_json_metric_report_format(self.sut, [e])
        result = get_result(
            self.sut, Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
            '', '')
        self.assertIsNotNone(result)
        self.assertEqual(Result.PASS, result['result'])

    @mock.patch('assertions.service_details.utils.discover_ssdp')
    def test_test_service_details_cover(self, mock_discover_ssdp):
        service.test_service_details(self.sut)


if __name__ == '__main__':
    unittest.main()
