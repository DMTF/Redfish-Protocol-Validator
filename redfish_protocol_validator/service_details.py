# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import json
import time
from urllib.parse import urlparse

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, RequestType, Result
from redfish_protocol_validator.constants import SSDP_ALL, SSDP_REDFISH
from redfish_protocol_validator.system_under_test import SystemUnderTest


def test_event_service_subscription(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_EVENT_POST_RESP."""
    if sut.subscriptions_uri:
        payload = {
            'Context': 'RPV test subscription',
            'Protocol': 'Redfish',
            'Destination': 'https://192.168.1.50/Destination1'
        }
        response = sut.session.post(sut.rhost + sut.subscriptions_uri,
                                    json=payload)
        sut.add_response(sut.subscriptions_uri, response,
                         request_type=RequestType.SUBSCRIPTION)
        if response.status_code == requests.codes.CREATED:
            location = response.headers.get('Location')
            if location:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, sut.subscriptions_uri,
                        Assertion.SERV_EVENT_POST_RESP, 'Test passed')
                # cleanup
                uri = urlparse(location).path
                r = sut.session.delete(sut.rhost + uri)
                sut.add_response(uri, r, request_type=RequestType.SUBSCRIPTION)
            else:
                msg = ('Response from event subscription POST request to %s '
                       'did not include a Location header for the newly '
                       'created subscription resource URI' %
                       sut.subscriptions_uri)
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, sut.subscriptions_uri,
                        Assertion.SERV_EVENT_POST_RESP, msg)
        else:
            msg = ('Response from event subscription POST request to %s '
                   'returned status code %s; expected %s; extended error: %s'
                   % (sut.subscriptions_uri, response.status_code,
                      requests.codes.CREATED,
                      utils.get_extended_error(response)))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_POST_RESP, msg)
    else:
        msg = ('No event subscriptions URI found on the service; unable to '
               'test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_EVENT_POST_RESP, msg)


def test_push_style_eventing(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_EVENT_PUSH_STYLE."""
    pass


def test_event_error_on_bad_request(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST."""
    if sut.subscriptions_uri:
        payload = {
            'Context': 'RPV test subscription',
            'Protocol': 'FTP',  # invalid EventDestinationProtocol
            'Destination': 'https://192.168.1.50/Destination1'
        }
        response = sut.session.post(sut.rhost + sut.subscriptions_uri,
                                    json=payload)
        sut.add_response(sut.subscriptions_uri, response,
                         request_type=RequestType.SUBSCRIPTION)
        if response.ok:
            msg = ('Event subscription request with bad Protocol parameter '
                   '(FTP) to %s returned status code %s; expected %s' % (
                       sut.subscriptions_uri, response.status_code,
                       requests.codes.BAD_REQUEST))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, msg)
            location = response.headers.get('Location')
            if location:
                # cleanup
                uri = urlparse(location).path
                r = sut.session.delete(sut.rhost + uri)
                sut.add_response(uri, r, request_type=RequestType.SUBSCRIPTION)
        elif response.status_code == requests.codes.BAD_REQUEST:
            sut.log(Result.PASS, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, 'Test passed')
        else:
            msg = ('Event subscription request with bad Protocol parameter '
                   '(FTP) to %s returned status code %s; expected %s' % (
                       sut.subscriptions_uri, response.status_code,
                       requests.codes.BAD_REQUEST))
            sut.log(Result.WARN, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, msg)
    else:
        msg = ('No event subscriptions URI found on the service; unable to '
               'test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_EVENT_ERROR_ON_BAD_REQUEST, msg)


def test_event_error_on_mutually_excl_props(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS."""
    if sut.subscriptions_uri:
        payload = {
            'Context': 'RPV test subscription',
            'Protocol': 'Redfish',
            'Destination': 'https://192.168.1.50/Destination1',
            'RegistryPrefixes': [
                'Base'
            ],
            'MessageIds': [
                'Base.1.0.Success',
                'Base.1.0.GeneralError'
            ]
        }
        response = sut.session.post(sut.rhost + sut.subscriptions_uri,
                                    json=payload)
        sut.add_response(sut.subscriptions_uri, response,
                         request_type=RequestType.SUBSCRIPTION)
        if response.ok:
            msg = ('Event subscription request with mutually exclusive '
                   'properties (RegistryPrefixes and MessageIds) to %s '
                   'returned status code %s; expected %s' % (
                       sut.subscriptions_uri, response.status_code,
                       requests.codes.BAD_REQUEST))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, msg)
            location = response.headers.get('Location')
            if location:
                # cleanup
                uri = urlparse(location).path
                r = sut.session.delete(sut.rhost + uri)
                sut.add_response(uri, r, request_type=RequestType.SUBSCRIPTION)
        elif response.status_code == requests.codes.BAD_REQUEST:
            sut.log(Result.PASS, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS,
                    'Test passed')
        else:
            msg = ('Event subscription request with mutually exclusive '
                   'properties (RegistryPrefixes and MessageIds) to %s '
                   'returned status code %s; expected %s' % (
                       sut.subscriptions_uri, response.status_code,
                       requests.codes.BAD_REQUEST))
            sut.log(Result.WARN, response.request.method,
                    response.status_code, sut.subscriptions_uri,
                    Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, msg)
    else:
        msg = ('No event subscriptions URI found on the service; unable to '
               'test this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_EVENT_ERROR_MUTUALLY_EXCL_PROPS, msg)


def pre_ssdp(sut: SystemUnderTest):
    """Perform prerequisite SSDP steps"""
    # discover using the redfish search target
    services = utils.discover_ssdp(search_target=SSDP_REDFISH)
    sut.add_ssdp_services(SSDP_REDFISH, services)

    # discover using the ssdp:all search target
    services = utils.discover_ssdp(search_target=SSDP_ALL)
    sut.add_ssdp_services(SSDP_ALL, services)

    # determine SSDP enabled/disabled state
    if sut.mgr_net_proto_uri:
        r = sut.session.get(sut.rhost + sut.mgr_net_proto_uri)
        if r.ok:
            sut.add_response(sut.mgr_net_proto_uri, r)
            d = r.json()
            if 'SSDP' in d and 'ProtocolEnabled' in d['SSDP']:
                enabled = d['SSDP']['ProtocolEnabled']
                sut.set_ssdp_enabled(enabled)


def test_ssdp_can_be_disabled(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSDP_CAN_BE_DISABLED."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)
        return

    if not sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid):
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)
        return

    if not sut.mgr_net_proto_uri:
        msg = ('ManagerNetworkProtocol URL not found; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)
        return

    r = sut.get_response('GET', sut.mgr_net_proto_uri)
    if r and sut.ssdp_enabled:
        # Attempt to disable SSDP
        payload = {'SSDP': {'ProtocolEnabled': False}}
        etag = r.headers.get('ETag')
        headers = {'If-Match': etag} if etag else {}
        r = sut.session.patch(sut.rhost + sut.mgr_net_proto_uri,
                              json=payload, headers=headers)
        if r.ok:
            services = utils.discover_ssdp(search_target=SSDP_REDFISH)
            uuids = services.keys()
            if sut.service_uuid not in uuids:
                sut.log(Result.PASS, 'PATCH', r.status_code,
                        sut.mgr_net_proto_uri,
                        Assertion.SERV_SSDP_CAN_BE_DISABLED,
                        'Test passed')
            else:
                msg = ('Service responded to SSDP query after '
                       'disabling SSDP')
                sut.log(Result.FAIL, 'PATCH', r.status_code,
                        sut.mgr_net_proto_uri,
                        Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)
            # Re-enable SSDP
            payload = {'SSDP': {'ProtocolEnabled': True}}
            etag = r.headers.get('ETag')
            headers = {'If-Match': etag} if etag else {}
            sut.session.patch(sut.rhost + sut.mgr_net_proto_uri,
                              json=payload, headers=headers)
        else:
            msg = 'Attempt to disable SSDP failed'
            sut.log(Result.FAIL, 'PATCH', r.status_code,
                    sut.mgr_net_proto_uri,
                    Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)
    else:
        msg = ('SSDP does not appear to be enabled; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_CAN_BE_DISABLED, msg)


def test_ssdp_usn_matches_service_root_uuid(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID, msg)
        return

    if sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid):
        service = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)

        sut.log(Result.PASS, '', '', service.get('USN'),
                Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                'Test passed')
        return

    if sut.get_ssdp_services(SSDP_REDFISH):
        services = sut.get_ssdp_services(SSDP_REDFISH)
        for uuid, service in services.items():
            url = service.get('AL')
            if url:
                if urlparse(url).netloc == urlparse(sut.rhost).netloc:
                    msg = ('No SSDP response was found for Service Root UUID '
                           '%s, but a response was found for UUID %s with '
                           'Service Root URL %s; the service appears to be '
                           'responding with an incorrect UUID' % (
                            sut.service_uuid, uuid, url))
                    sut.log(Result.FAIL, '', '', service.get('USN'),
                            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID,
                            msg)
                    return

    msg = ('No SSDP responses found matching this service; unable to test '
           'this assertion')
    sut.log(Result.NOT_TESTED, '', '', '',
            Assertion.SERV_SSDP_USN_MATCHES_SERVICE_ROOT_UUID, msg)


def test_ssdp_uuid_in_canonical_format(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT, msg)
        return

    service = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)
    if not service:
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT, msg)
        return

    uuid = utils.uuid_from_usn(service.get('USN'), utils.redfish_usn_pattern)
    if uuid:
        sut.log(Result.PASS, '', '', service.get('USN'),
                Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT,
                'Test passed')
    else:
        msg = ('The unique ID found (%s) does not match the regex pattern "%s"'
               % (service.get('USN'), utils.redfish_usn_pattern.pattern))
        sut.log(Result.FAIL, '', '', service.get('USN'),
                Assertion.SERV_SSDP_UUID_IN_CANONICAL_FORMAT, msg)


def test_ssdp_msearch_responds_to_redfish_or_all(sut: SystemUnderTest):
    """Perform tests for
    Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL, msg)
        return

    service_redfish = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)
    service_ssdp_all = sut.get_ssdp_service(SSDP_ALL, sut.service_uuid)

    if service_redfish and service_ssdp_all:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL,
                'Test passed')
    elif service_redfish:
        msg = ('SSDP response found for Search Target (ST) of the Redfish '
               'Service, but not found for ST of ssdp:all')
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL, msg)
    elif service_ssdp_all:
        msg = ('SSDP response found for Search Target (ST) of ssdp:all, but '
               'not found for ST of the Redfish Service')
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL, msg)
    else:
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_MSEARCH_RESPONDS_TO_REDFISH_OR_ALL, msg)


def test_ssdp_st_header_format(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSDP_ST_HEADER_FORMAT."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_ST_HEADER_FORMAT, msg)
        return

    service = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)
    if not service:
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_ST_HEADER_FORMAT, msg)
        return

    st_header = service.get('ST')
    if not st_header:
        msg = 'ST header not found in M-SEARCH response'
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSDP_ST_HEADER_FORMAT, msg)
        return

    m = utils.redfish_st_pattern.search(st_header)
    if not m:
        msg = ('Returned ST header "%s" does not match the regex pattern "%s"'
               % (st_header, utils.redfish_st_pattern.pattern))
        sut.log(Result.FAIL, '', '', st_header,
                Assertion.SERV_SSDP_ST_HEADER_FORMAT, msg)
        return

    st_minor = 0
    msg_minor = 'missing'
    if m.group(1):
        st_minor = int(m.group(1).lstrip(':'))
        msg_minor = str(st_minor)
    # if the service minor ver is non-zero, must be included in the ST header
    if sut.version_tuple.minor != 0 and sut.version_tuple.minor != st_minor:
        # FAIL minor version incorrectly specified in ST header
        msg = ('The Redfish protocol minor version from the Service Root is '
               '%s, but the minor version in the ST header is %s'
               % (sut.version_tuple.minor, msg_minor))
        sut.log(Result.FAIL, '', '', st_header,
                Assertion.SERV_SSDP_ST_HEADER_FORMAT, msg)
        return

    # PASS if we have not already logged a result and returned
    sut.log(Result.PASS, '', '', st_header,
            Assertion.SERV_SSDP_ST_HEADER_FORMAT, 'Test passed')


def test_ssdp_al_header_points_to_service_root(sut: SystemUnderTest):
    """Perform tests for
    Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT, msg)
        return

    service = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)
    if not service:
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT, msg)
        return

    url = service.get('AL')
    if not url:
        msg = 'AL header not found in M-SEARCH response'
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT, msg)
        return

    if urlparse(url).path in ('/redfish/v1', '/redfish/v1/'):
        sut.log(Result.PASS, '', '', url,
                Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT,
                'Test passed')
    else:
        msg = ('AL header "%s" does appear to be a Service Root URL; expected '
               'the path to be "/redfish/v1/"' % url)
        sut.log(Result.FAIL, '', '', url,
                Assertion.SERV_SSDP_AL_HEADER_POINTS_TO_SERVICE_ROOT, msg)


def test_ssdp_m_search_response_format(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT."""
    if not sut.service_uuid:
        msg = ('Service UUID not found in Service Root; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT, msg)
        return

    service = sut.get_ssdp_service(SSDP_REDFISH, sut.service_uuid)
    if not service:
        msg = 'Service not found via SSDP; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT, msg)
        return

    errors = ''
    cache_control = service.get('CACHE-CONTROL')
    if not cache_control:
        errors += ' No CACHE-CONTROL header found.'
    else:
        prop, max_age = cache_control.split('=')
        prop = prop.strip()
        max_age = max_age.strip()
        if prop != 'max-age' or not max_age.isdigit() or int(max_age) < 1800:
            errors += (' CACHE-CONTROL header is "%s"; expected format '
                       '"max-age=<seconds, at least 1800>".' % cache_control)

    # format of ST, USN and AL headers already checked in other assertions
    # just check presence/absence
    st = service.get('ST')
    if not st:
        errors += ' No ST header found.'

    usn = service.get('USN')
    if not usn:
        errors += ' No USN header found.'

    al = service.get('AL')
    if not al:
        errors += ' No AL header found.'

    if errors:
        msg = 'One or more errors found with M-SEARCH response:' + errors
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT, msg)
    else:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSDP_M_SEARCH_RESPONSE_FORMAT, 'Test passed')


def test_sse_successful_response(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSE_SUCCESSFUL_RESPONSE."""
    if not sut.server_sent_event_uri:
        msg = 'No ServerSentEventUri available; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, msg)
        return

    response = sut.get_response('GET', sut.server_sent_event_uri,
                                request_type=RequestType.STREAMING)
    if response is None:
        response, _ = utils.get_sse_stream(sut)

    if response is not None and response.ok:
        failed = False
        if response.status_code != requests.codes.OK:
            msg = ('Response from GET request to URL %s succeeded with status '
                   '%s; expected status %s' % (
                    sut.server_sent_event_uri, response.status_code,
                    requests.codes.OK))
            sut.log(Result.FAIL, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, msg)
            failed = True
        content_type = response.headers.get('Content-Type')
        if content_type:
            content_type = utils.normalize_media_type(content_type)
            if content_type not in ['text/event-stream',
                                    'text/event-stream;charset=utf-8']:
                msg = ('Content-Type header in response from GET request to '
                       'URL %s was %s; expected %s or %s' %
                       (sut.server_sent_event_uri, content_type,
                        'text/event-stream', 'text/event-stream;charset=utf-8')
                       )
                sut.log(Result.FAIL, 'GET', response.status_code,
                        sut.server_sent_event_uri,
                        Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, msg)
                failed = True
        else:
            msg = ('No Content-Type header in response from GET request to '
                   'URL %s; expected %s or %s' %
                   (sut.server_sent_event_uri, 'text/event-stream',
                    'text/event-stream;charset=utf-8'))
            sut.log(Result.FAIL, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, msg)
            failed = True
        if not failed:
            sut.log(Result.PASS, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, 'Test passed')
        # return successful response for use in subsequent assertions
        return response
    else:
        msg = ('Response from GET request to URL %s was not successful; '
               'unable to test this assertion' % sut.server_sent_event_uri)
        code = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, 'GET', code, sut.server_sent_event_uri,
                Assertion.SERV_SSE_SUCCESSFUL_RESPONSE, msg)


def test_sse_unsuccessful_response(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE."""
    if not sut.server_sent_event_uri:
        msg = 'No ServerSentEventUri available; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
        return

    response = None
    exc_name = ''
    try:
        response = sut.session.get(sut.rhost + sut.server_sent_event_uri,
                                   headers={'Accept': 'application/json'},
                                   stream=True)
    except Exception as e:
        exc_name = e.__class__.__name__
    if response is None:
        msg = ('Caught %s while opening SSE stream with incorrect Accept '
               'header of "application/json"; expected response with status '
               'code of 400 or greater' % exc_name)
        sut.log(Result.FAIL, 'GET', '', sut.server_sent_event_uri,
                Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
    elif response.ok:
        msg = ('Response from GET request to URL %s was successful; unable to '
               'test this assertion' % sut.server_sent_event_uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                sut.server_sent_event_uri,
                Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
        # close the SSE stream
        response.close()
    else:
        failed = False
        content_type = response.headers.get('Content-Type')
        if content_type:
            content_type = utils.normalize_media_type(content_type)
            if content_type not in ['application/json',
                                    'application/json;charset=utf-8']:
                msg = ('Content-Type header in response from GET request to '
                       'URL %s was %s; expected %s or %s' %
                       (sut.server_sent_event_uri, content_type,
                        'application/json', 'application/json;charset=utf-8')
                       )
                sut.log(Result.FAIL, 'GET', response.status_code,
                        sut.server_sent_event_uri,
                        Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
                failed = True
            else:
                errors = ''
                data = response.json()
                if 'error' in data and isinstance(data['error'], dict):
                    if 'code' not in data['error']:
                        errors += (' Property "code" missing from "error" '
                                   'complex property.')
                    elif not isinstance(data['error']['code'], str):
                        errors += ' Property "code" is not a string.'
                    if 'message' not in data['error']:
                        errors += (' Property "message" missing from "error" '
                                   'complex property.')
                    elif not isinstance(data['error']['message'], str):
                        errors += ' Property "message" is not a string.'
                    if '@Message.ExtendedInfo' not in data['error']:
                        errors += (
                            ' Property "@Message.ExtendedInfo" missing from '
                            '"error" complex property.')
                    elif not isinstance(data['error']['@Message.ExtendedInfo'],
                                        list):
                        errors += (' Property "@Message.ExtendedInfo" is not '
                                   'a list.')
                else:
                    errors += (' Property "error" is missing from response '
                               'body or is not a complex property.')
                if errors:
                    msg = ('One or more problems found with error response:' +
                           errors)
                    sut.log(Result.FAIL, 'GET', response.status_code,
                            sut.server_sent_event_uri,
                            Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
                    failed = True
        else:
            msg = ('No Content-Type header in response from GET request to '
                   'URL %s; expected %s or %s' %
                   (sut.server_sent_event_uri, 'application/json',
                    'application/json;charset=utf-8'))
            sut.log(Result.FAIL, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, msg)
            failed = True

        if not failed:
            sut.log(Result.PASS, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SERV_SSE_UNSUCCESSFUL_RESPONSE, 'Test passed')


def read_sse_events(sse_response):
    if sse_response is None:
        return None
    client = utils.SSEClientTimeout(sse_response, timeout=3)
    events = []
    for event in client.events():
        events.append(event)
    return events


def test_sse_blank_lines_between_events(sut: SystemUnderTest, events):
    """Perform tests for Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS."""
    if events is None:
        msg = 'No ServerSentEvent stream opened; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS, msg)
        return

    if not len(events):
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS, msg)
        return

    try:
        for event in events:
            json.loads(event.data)
    except json.decoder.JSONDecodeError:
        msg = 'Blank line not found between events'
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS, msg)
    else:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_BLANK_LINES_BETWEEN_EVENTS,
                'Test passed')


def test_sse_connection_open_until_closed(sut: SystemUnderTest, sse_response):
    """Perform tests for Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED."""
    if sse_response is None:
        msg = 'No ServerSentEvent stream opened; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED, msg)
        return

    sse_response.close()
    for _ in sse_response:
        msg = 'After closing SSE stream, connection appears to still be open'
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED, msg)
        break
    else:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_CONNECTION_OPEN_UNTIL_CLOSED, 'Test passed')


def test_sse_event_dest_deleted_on_close(sut: SystemUnderTest, response):
    """Perform tests for Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE."""
    if response is None:
        msg = 'No ServerSentEvent stream opened; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE, msg)
        return

    if not sut.event_dest_uri:
        msg = 'No EventDestination URI found; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE, msg)
        return

    # response closed above in assertion test_sse_connection_open_until_closed

    # wait for up to 60 seconds for EventDestination resource to be deleted
    status = requests.codes.OK
    for i in range(60):
        r = sut.session.get(sut.rhost + sut.event_dest_uri)
        if r.ok:
            # resource still present
            status = r.status_code
        elif r.status_code == requests.codes.NOT_FOUND:
            sut.log(Result.PASS, 'GET', r.status_code, sut.event_dest_uri,
                    Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE,
                    'Test passed')
            return
        else:
            msg = ('Unexpected status on GET to EventDestination resource; '
                   'unable to test this assertion')
            sut.log(Result.NOT_TESTED, 'GET', r.status_code,
                    sut.event_dest_uri,
                    Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE, msg)
            return
        time.sleep(1)

    # if we didn't return in the above loop, resource was still present
    msg = 'EventDestination resource not deleted when SSE stream closed'
    sut.log(Result.FAIL, 'GET', status, sut.event_dest_uri,
            Assertion.SERV_SSE_EVENT_DEST_DELETED_ON_CLOSE, msg)


def test_sse_events_sent_via_open_connection(sut: SystemUnderTest, events):
    """Perform tests for Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION."""
    if not events:
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION, msg)
    else:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_EVENTS_SENT_VIA_OPEN_CONNECTION,
                'Test passed')


def test_sse_open_creates_event_dest(sut: SystemUnderTest):
    """Perform tests for Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST."""
    if not sut.server_sent_event_uri:
        msg = 'No ServerSentEventUri available; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST, msg)
        return None, None

    if not sut.subscriptions_uri:
        msg = ('No EventService Subscriptions URI available; unable to test '
               'this assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST, msg)
        return None, None

    response, event_dest_uri = utils.get_sse_stream(sut)

    if response is not None and response.ok:
        if event_dest_uri:
            sut.log(Result.PASS, '', '', event_dest_uri,
                    Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST,
                    'Test passed')
            return response, event_dest_uri
        else:
            msg = ('Unable to locate a new EventDestination resource in the '
                   'Subscriptions collection')
            sut.log(Result.FAIL, '', '', '',
                    Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST, msg)
            # close the SSE stream now if we didn't locate the EventDestination
            response.close()
    else:
        msg = 'Open of SSE stream failed; unable to test this assertion'
        code = response.status_code if response is not None else ''
        sut.log(Result.NOT_TESTED, 'GET', code, sut.server_sent_event_uri,
                Assertion.SERV_SSE_OPEN_CREATES_EVENT_DEST, msg)
    return None, None


def test_sse_event_dest_context_opaque_str(sut: SystemUnderTest, event_dest):
    """Perform tests for Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR."""
    if not event_dest:
        msg = 'No EventDestination URI found; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR, msg)
        return

    r = sut.session.get(sut.rhost + event_dest)
    if r.status_code == requests.codes.OK:
        data = r.json()
        if 'Context' in data:
            context = data.get('Context')
            if isinstance(context, str):
                sut.log(Result.PASS, 'GET', r.status_code, event_dest,
                        Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR,
                        'Test passed')
            else:
                msg = ('The Context property from the EventDestination '
                       'resource is not a string (value: %s)' % context)
                sut.log(Result.FAIL, 'GET', r.status_code, event_dest,
                        Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR, msg)
        else:
            msg = (
                'The required property Context was missing from the '
                'EventDestination resource')
            sut.log(Result.FAIL, 'GET', r.status_code, event_dest,
                    Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR, msg)
    else:
        msg = ('Failed to read the EventDestination URI; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, 'GET', r.status_code, event_dest,
                Assertion.SERV_SSE_EVENT_DEST_CONTEXT_OPAQUE_STR, msg)


def test_sse_close_connection_if_event_dest_deleted(
        sut: SystemUnderTest, sse_response, event_dest_uri):
    """Perform tests for
    Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED."""
    if sse_response is None:
        msg = 'No ServerSentEvent stream opened; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED, msg)
        return

    if not event_dest_uri:
        msg = ('No EventDestination resource found; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED, msg)
        return

    r = sut.session.delete(sut.rhost + event_dest_uri)
    if r.ok:
        # give the service up to 5 seconds to close the stream
        for _ in range(5):
            time.sleep(1)
            for _ in sse_response:
                break
            else:
                sut.log(
                    Result.PASS, 'DELETE', r.status_code, event_dest_uri,
                    Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
                    'Test passed')
                return
        # if we didn't return in the loop above, the connection wasn't closed
        msg = ('After deleting the EventDestination resource, the '
               'connection appears to still be open')
        sut.log(Result.FAIL, 'DELETE', r.status_code, event_dest_uri,
                Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED,
                msg)
    else:
        msg = 'Delete of EventDestination resource %s failed' % event_dest_uri
        sut.log(Result.FAIL, 'DELETE', r.status_code, event_dest_uri,
                Assertion.SERV_SSE_CLOSE_CONNECTION_IF_EVENT_DEST_DELETED, msg)


def test_sse_id_uniquely_identifies_payload(sut: SystemUnderTest, events):
    """Perform tests for
    Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD."""
    if not events:
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD, msg)
        return

    missing_id_list = [e for e in events if e.data and not e.id]
    id_list = [e.id for e in events if e.data]
    id_set = set(id_list)

    if len(missing_id_list):
        msg = ('%s out of %s event payloads did not have an id field' %
               (len(missing_id_list), len(id_list)))
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD, msg)
        return

    if len(id_list) == len(id_set):
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD,
                'Test passed')
    else:
        msg = 'More than one event used the same id field'
        sut.log(Result.FAIL, '', '', '',
                Assertion.SERV_SSE_ID_FIELD_UNIQUELY_IDENTIFIES_PAYLOAD, msg)


def test_sse_data_based_on_payload_format(sut: SystemUnderTest, events):
    """Perform tests for
    Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT."""
    if not events:
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT, msg)
        return

    failed = False
    for event in events:
        try:
            data = json.loads(event.data)
            if '@odata.type' in data:
                t = data.get('@odata.type').rsplit('.')[-1]
                if t not in ['Event', 'MetricReport']:
                    failed = True
                    msg = ('Event %s had payload format %s; expected %s '
                           'or %s' % (event.id, t, 'Event',
                                      'MetricReport'))
                    sut.log(
                        Result.FAIL, '', '', '',
                        Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT,
                        msg)
        except Exception:
            # ignore for this assertion; JSON checked in subsequent assertion
            pass

    if not failed:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_DATA_FIELD_BASED_ON_PAYLOAD_FORMAT,
                'Test passed')


def test_sse_json_event_message_format(sut: SystemUnderTest, events):
    """Perform tests for Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT."""
    if not events:
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT, msg)
        return

    failed = False
    event_found = False
    for event in events:
        if event.data and '#Event' in event.data:
            try:
                data = json.loads(event.data)
                t = data.get('@odata.type', '').rsplit('.')[-1]
                if t == 'Event':
                    event_found = True
            except json.decoder.JSONDecodeError as e:
                failed = True
                msg = ('JSON decode error of Event payload for event %s: %s' %
                       (event.id, e))
                sut.log(
                    Result.FAIL, '', '', '',
                    Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
                    msg)

    if event_found and not failed:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT,
                'Test passed')
    if not event_found and not failed:
        msg = 'No Event object payload found; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_JSON_EVENT_MESSAGE_FORMAT, msg)


def test_sse_json_metric_report_format(sut: SystemUnderTest, events):
    """Perform tests for Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT."""
    if not events:
        msg = 'No ServerSentEvent events read; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT, msg)
        return

    failed = False
    event_found = False
    for event in events:
        if event.data and '#MetricReport' in event.data:
            try:
                data = json.loads(event.data)
                t = data.get('@odata.type', '').rsplit('.')[-1]
                if t == 'MetricReport':
                    event_found = True
            except json.decoder.JSONDecodeError as e:
                failed = True
                msg = ('JSON decode error of MetricReport payload for '
                       'event %s: %s' % (event.id, e))
                sut.log(
                    Result.FAIL, '', '', '',
                    Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
                    msg)

    if event_found and not failed:
        sut.log(Result.PASS, '', '', '',
                Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT,
                'Test passed')
    if not event_found and not failed:
        msg = ('No MetricReport object payload found; unable to test this '
               'assertion')
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SERV_SSE_JSON_METRIC_REPORT_FORMAT, msg)


def test_eventing(sut: SystemUnderTest):
    """Perform eventing tests"""
    test_event_service_subscription(sut)
    test_push_style_eventing(sut)
    test_event_error_on_bad_request(sut)
    test_event_error_on_mutually_excl_props(sut)


def test_discovery(sut: SystemUnderTest):
    """Perform service discovery tests"""
    pre_ssdp(sut)
    test_ssdp_can_be_disabled(sut)
    test_ssdp_usn_matches_service_root_uuid(sut)
    test_ssdp_uuid_in_canonical_format(sut)
    test_ssdp_msearch_responds_to_redfish_or_all(sut)
    test_ssdp_st_header_format(sut)
    test_ssdp_al_header_points_to_service_root(sut)
    test_ssdp_m_search_response_format(sut)


def test_server_sent_events(sut: SystemUnderTest):
    """Perform server sent event tests"""
    response = test_sse_successful_response(sut)
    test_sse_unsuccessful_response(sut)
    events = read_sse_events(response)
    test_sse_blank_lines_between_events(sut, events)
    test_sse_connection_open_until_closed(sut, response)
    test_sse_event_dest_deleted_on_close(sut, response)
    test_sse_events_sent_via_open_connection(sut, events)
    response, event_dest = test_sse_open_creates_event_dest(sut)
    test_sse_event_dest_context_opaque_str(sut, event_dest)
    test_sse_close_connection_if_event_dest_deleted(sut, response, event_dest)
    test_sse_id_uniquely_identifies_payload(sut, events)
    test_sse_data_based_on_payload_format(sut, events)
    test_sse_json_event_message_format(sut, events)
    test_sse_json_metric_report_format(sut, events)


def test_service_details(sut: SystemUnderTest):
    """Perform tests from the 'Service details' section of the spec."""
    test_eventing(sut)
    test_discovery(sut)
    test_server_sent_events(sut)
