# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
import random

import requests

from redfish_protocol_validator import accounts as acct
from redfish_protocol_validator import sessions
from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import RequestType, ResourceType
from redfish_protocol_validator.system_under_test import SystemUnderTest


def set_mfr_model_fw(sut: SystemUnderTest, data):
    sep_uuid = data.get('ServiceEntryPointUUID', '').lower()
    if (sut.model is None or
            (sut.service_uuid and sut.service_uuid == sep_uuid)):
        sut.set_manufacturer(data.get('Manufacturer', 'N/A'))
        sut.set_model(data.get('Model', 'N/A'))
        sut.set_firmware_version(data.get('FirmwareVersion', 'N/A'))


def set_mgr_net_proto_uri(sut: SystemUnderTest, data):
    sep_uuid = data.get('ServiceEntryPointUUID', '').lower()
    if (sut.mgr_net_proto_uri is None or
            (sut.service_uuid and sut.service_uuid == sep_uuid)):
        sut.set_mgr_net_proto_uri(
            data.get('NetworkProtocol', {}).get('@odata.id', ''))


def find_certificates(sut: SystemUnderTest, data):
    uri = data.get('NetworkProtocol', {}).get('@odata.id')
    if uri:
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}
        if r.ok:
            d = utils.get_response_json(r)
            coll_uri = d.get('HTTPS', {}).get('Certificates', {}).get('@odata.id')
            if coll_uri:
                r = sut.get(coll_uri)
                yield {'uri': coll_uri, 'response': r}
                if r.ok:
                    d = utils.get_response_json(r)
                    for m in d.get('Members', []):
                        uri = m.get('@odata.id')
                        if uri:
                            # uncomment next 2 lines if we need to read certs
                            # r = sut.get(uri)
                            # yield {'uri': uri, 'response': r}
                            sut.add_cert(coll_uri, uri)


def get_default_resources(sut: SystemUnderTest, uri='/redfish/v1/',
                          uris=None):
    """
    Generator function to retrieve the default set of resources to test

    :param sut: SystemUnderTest object
    :param uri: the starting URI (default is '/redfish/v1/')
    :param uris: a list of specific URIs to retrieve
    :return: dict elements containing the URI and `requests` response
    """
    # do GETs on spec-defined URIs
    yield {'uri': '/redfish', 'response': sut.get('/redfish')}
    yield {'uri': '/redfish/v1/odata', 'response':
           sut.get('/redfish/v1/odata')}
    yield {'uri': '/redfish/v1', 'response':
           sut.get('/redfish/v1')}
    yield {'uri': '/redfish/v1/$metadata', 'response':
           sut.get('/redfish/v1/$metadata',
                   headers={'accept': 'application/xml'})}
    yield {'uri': '/redfish/v1/openapi.yaml',
           'request_type': RequestType.YAML,
           'response': sut.get('/redfish/v1/openapi.yaml',
                               headers={'accept': 'application/yaml'})}

    # do HEAD on the service root
    r = sut.head(uri)
    yield {'uri': uri, 'response': r}
    # do GET on the service root
    r = sut.get(uri)
    yield {'uri': uri, 'response': r}
    root = utils.get_response_json(r) if r.status_code == requests.codes.OK else {}

    sut.set_version(root.get('RedfishVersion', '1.0.0'))
    sut.set_product(root.get('Product', 'N/A'))
    sut.set_service_uuid(root.get('UUID'))
    sut.set_supported_query_params(root.get('ProtocolFeaturesSupported', {}))

    for prop in ['Systems', 'Chassis']:
        uri = root.get(prop, {}).get('@odata.id')
        if uri:
            sut.set_nav_prop_uri(prop, uri)
            r = sut.get(uri)
            yield {'uri': uri, 'response': r}
            if r.ok:
                data = utils.get_response_json(r)
                if 'Members' in data and len(data['Members']):
                    uri = data['Members'][0].get('@odata.id')
                    if uri:
                        r = sut.get(uri)
                        yield {'uri': uri, 'response': r}

    uri = root.get('Managers', {}).get('@odata.id')
    if uri:
        sut.set_nav_prop_uri('Managers', uri)
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}
        if r.ok:
            data = utils.get_response_json(r)
            for m in data.get('Members', []):
                uri = m.get('@odata.id')
                if uri:
                    r = sut.get(uri)
                    yield {'uri': uri, 'response': r}
                    if r.ok:
                        d = utils.get_response_json(r)
                        set_mfr_model_fw(sut, d)
                        set_mgr_net_proto_uri(sut, d)
                        for c in find_certificates(sut, d):
                            yield c

    uri = root.get('AccountService', {}).get('@odata.id')
    if uri:
        sut.set_nav_prop_uri('AccountService', uri)
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}
        if r.ok:
            data = utils.get_response_json(r)
            uri = data.get('PrivilegeMap', {}).get('@odata.id')
            if uri:
                sut.set_nav_prop_uri('PrivilegeMap', uri)
            for prop in ['Accounts', 'Roles']:
                uri = data.get(prop, {}).get('@odata.id')
                if uri:
                    r = sut.get(uri)
                    yield {'uri': uri, 'response': r}
                    sut.set_nav_prop_uri(prop, uri)
                    if r.ok:
                        d = utils.get_response_json(r)
                        if prop == 'Accounts':
                            resource_type = ResourceType.MANAGER_ACCOUNT
                            # get accounts up to sut.username
                            for m in d.get('Members', []):
                                uri = m.get('@odata.id')
                                if uri:
                                    r = sut.get(uri)
                                    yield {'uri': uri, 'response': r,
                                           'resource_type': resource_type}
                                    if r.ok:
                                        sut.add_user(utils.get_response_json(r))
                                        if (utils.get_response_json(r).get('UserName')
                                                == sut.username):
                                            break

                        else:
                            resource_type = ResourceType.ROLE
                            # get all the roles
                            for m in d.get('Members', []):
                                uri = m.get('@odata.id')
                                if uri:
                                    r = sut.get(uri)
                                    yield {'uri': uri, 'response': r,
                                           'resource_type': resource_type}
                                    if r.ok:
                                        sut.add_role(utils.get_response_json(r))

    uri = root.get('SessionService', {}).get('@odata.id')
    if uri:
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}
        if r.ok:
            data = utils.get_response_json(r)
            uri = data.get('Sessions', {}).get('@odata.id')
            if uri:
                r = sut.get(uri)
                yield {'uri': uri, 'response': r}
                if r.ok:
                    data = utils.get_response_json(r)
                    if 'Members' in data and len(data['Members']):
                        uri = data['Members'][0].get('@odata.id')
                        if uri:
                            r = sut.get(uri)
                            yield {'uri': uri, 'response': r}

    uri = root.get('EventService', {}).get('@odata.id')
    if uri:
        sut.set_nav_prop_uri('EventService', uri)
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}
        if r.ok:
            data = utils.get_response_json(r)
            uri = data.get('Subscriptions', {}).get('@odata.id')
            if uri:
                sut.set_nav_prop_uri('Subscriptions', uri)
            uri = data.get('ServerSentEventUri')
            if uri:
                sut.set_server_sent_event_uri(uri)
                r, event_dest_uri = utils.get_sse_stream(sut)
                if event_dest_uri:
                    sut.set_event_dest_uri(event_dest_uri)
                if r is not None:
                    yield {'uri': uri, 'response': r,
                           'request_type': RequestType.STREAMING}

    uri = root.get('CertificateService', {}).get('@odata.id')
    if uri:
        sut.set_nav_prop_uri('CertificateService', uri)
        r = sut.get(uri)
        yield {'uri': uri, 'response': r}


def read_target_resources(sut: SystemUnderTest, uri='/redfish/v1/',
                          uris=None, func=get_default_resources):
    """
    Read the target resources using the specified generator function

    :param sut: SystemUnderTest object
    :param uri: the starting URI (default is '/redfish/v1/')
    :param uris: a list of specific URIs to retrieve
    :param func: generator function (`get_default_resources`,
        `get_all_resources`, or `get_select_resources`)
    """
    for r in func(sut, uri=uri, uris=uris):
        response = r['response']
        uri = r['uri']
        resource_type = r.get('resource_type')
        request_type = r.get('request_type', RequestType.NORMAL)
        sut.add_response(uri, response, resource_type=resource_type,
                         request_type=request_type)


def create_account(sut: SystemUnderTest, session,
                   request_type=RequestType.NORMAL):
    # Create test account
    user, password, new_acct_uri = acct.add_account(sut, session,
                                                    request_type=request_type)
    return user, password, new_acct_uri


def patch_account(sut: SystemUnderTest, session, acct_uri,
                  request_type=RequestType.NORMAL):
    # PATCH account
    return acct.patch_account(sut, session, acct_uri,
                              request_type=request_type)


def patch_other_account(sut: SystemUnderTest, session, user, password):
    """Create a new account and try to modify it with other creds"""
    new_user, new_password, new_acct_uri = None, None, None
    try:
        new_user, new_password, new_acct_uri = create_account(
            sut, session, request_type=RequestType.NORMAL)
        if new_acct_uri:
            new_session = requests.Session()
            new_session.auth = (user, password)
            new_session.verify = sut.verify
            pwd = patch_account(sut, new_session, new_acct_uri,
                                request_type=RequestType.MODIFY_OTHER)
            if pwd:
                new_password = pwd
    except Exception as e:
        logging.error('Caught exception while creating or patching other '
                      'account; Exception: %s; continuing with test' % str(e))
    return new_user, new_password, new_acct_uri


def delete_account(sut: SystemUnderTest, session, user, acct_uri,
                   request_type=RequestType.NORMAL):
    # DELETE account
    if acct_uri:
        acct.delete_account(sut, session, user, acct_uri,
                            request_type=request_type)


def data_modification_requests(sut: SystemUnderTest):
    new_session_uri, _ = sessions.create_session(sut)
    if new_session_uri:
        sessions.delete_session(sut, sut.session, new_session_uri,
                                request_type=RequestType.NORMAL)
    new_user, new_pwd, new_uri = None, None, None
    other_user, other_pwd, other_uri = None, None, None
    try:
        new_user, new_pwd, new_uri = create_account(
            sut, sut.session, request_type=RequestType.NORMAL)
        if new_uri:
            response = sut.get(new_uri)
            sut.add_response(new_uri, response)
            if response.ok:
                etag = utils.get_response_etag(response)
                data = utils.get_response_json(response)
                if 'PasswordChangeRequired' in data:
                    acct.password_change_required(sut, sut.session, new_user,
                                                  new_pwd, new_uri, data, etag)
            pwd = patch_account(sut, sut.session, new_uri,
                                request_type=RequestType.NORMAL)
            if pwd:
                new_pwd = pwd
            other_user, other_pwd, other_uri = patch_other_account(
                sut, sut.session, new_user, new_pwd)
    except Exception as e:
        logging.error('Caught exception while creating or patching accounts; '
                      'Exception: %s; continuing with test' % str(e))
    finally:
        if new_uri:
            delete_account(sut, sut.session, new_user, new_uri,
                           request_type=RequestType.NORMAL)
        if other_uri:
            delete_account(sut, sut.session, other_user, other_uri,
                           request_type=RequestType.NORMAL)


def data_modification_requests_no_auth(sut: SystemUnderTest, no_auth_session):
    new_session_uri, _ = sessions.create_session(sut)
    if new_session_uri:
        r = sessions.delete_session(sut, no_auth_session, new_session_uri,
                                    request_type=RequestType.NO_AUTH)
        if not r.ok:
            sessions.delete_session(sut, sut.session, new_session_uri,
                                    request_type=RequestType.NORMAL)
    user, password, new_acct_uri = create_account(
        sut, no_auth_session, request_type=RequestType.NO_AUTH)
    if not new_acct_uri:
        user, password, new_acct_uri = create_account(
            sut, sut.session, request_type=RequestType.NORMAL)
    if new_acct_uri:
        patch_account(sut, no_auth_session, new_acct_uri,
                      request_type=RequestType.NO_AUTH)
        delete_account(sut, no_auth_session, user, new_acct_uri,
                       request_type=RequestType.NO_AUTH)
        delete_account(sut, sut.session, user, new_acct_uri,
                       request_type=RequestType.NORMAL)


def unsupported_requests(sut: SystemUnderTest):
    # Data modification requests on the service root are never allowed
    uri = '/redfish/v1/'
    response = sut.delete(uri)
    sut.add_response(uri, response, request_type=RequestType.UNSUPPORTED_REQ)
    response = sut.patch(uri, json={})
    sut.add_response(uri, response, request_type=RequestType.UNSUPPORTED_REQ)
    response = sut.post(uri, json={})
    sut.add_response(uri, response, request_type=RequestType.UNSUPPORTED_REQ)
    # Unsupported HTTP methods return HTTP 501
    response = sut.request('FAKEMETHODFORTEST', uri)
    sut.add_response(uri, response, request_type=RequestType.UNSUPPORTED_REQ)


def basic_auth_requests(sut: SystemUnderTest):
    headers = {
        'OData-Version': '4.0'
    }
    uri = sut.sessions_uri
    # good request
    r = sut.get(uri, headers=headers, auth=(sut.username, sut.password),
                no_session=True)
    sut.add_response(uri, r, request_type=RequestType.BASIC_AUTH)


def http_requests(sut: SystemUnderTest):
    headers = {
        'OData-Version': '4.0'
    }
    if sut.scheme == 'http':
        http_rhost = sut.rhost
    elif sut.scheme == 'https':
        http_rhost = 'http' + sut.rhost[5:]
    else:
        logging.warning('Unexpected scheme (%s) for remote host %s found, '
                        'expected http or https; skipping http requests' %
                        (sut.scheme, sut.rhost))
        return

    redirect_msg = ('Caught %s while trying to trigger a redirect. To avoid '
                    'this warning and speed up the validation run, try adding '
                    'the --avoid-http-redirect command-line argument.')

    uri = '/redfish/v1/'
    if sut.scheme == 'http':
        # already using http, just fetch previous NO_AUTH response
        r = sut.get_response('GET', uri, request_type=RequestType.NO_AUTH)
        if r is not None:
            sut.add_response(uri, r, request_type=RequestType.HTTP_NO_AUTH)
    elif not sut.avoid_http_redirect:
        # request using HTTP and no auth (should fail or redirect to HTTPS)
        try:
            r = requests.get(http_rhost + uri, headers=headers,
                             verify=sut.verify)
            sut.add_response(uri, r, request_type=RequestType.HTTP_NO_AUTH)
        except Exception as e:
            logging.warning(redirect_msg % e.__class__.__name__)
            sut.set_avoid_http_redirect(True)

    uri = sut.sessions_uri
    if sut.scheme == 'http':
        # already using http, just fetch previous BASIC_AUTH response
        r = sut.get_response('GET', uri, request_type=RequestType.BASIC_AUTH)
        if r is not None:
            sut.add_response(uri, r, request_type=RequestType.HTTP_BASIC_AUTH)
        # already using http, just fetch previous NO_AUTH response
        r = sut.get_response('GET', uri, request_type=RequestType.NO_AUTH)
        if r is not None:
            sut.add_response(uri, r, request_type=RequestType.HTTP_NO_AUTH)
    elif not sut.avoid_http_redirect:
        # request using HTTP and basic auth (should fail or redirect to HTTPS)
        try:
            r = requests.get(http_rhost + uri, headers=headers,
                             auth=(sut.username, sut.password),
                             verify=sut.verify)
            sut.add_response(uri, r, request_type=RequestType.HTTP_BASIC_AUTH)
        except Exception as e:
            logging.warning(redirect_msg % e.__class__.__name__)
            sut.set_avoid_http_redirect(True)
        # request using HTTP and no auth (should fail or redirect to HTTPS)
        try:
            r = requests.get(http_rhost + uri, headers=headers,
                             verify=sut.verify)
            sut.add_response(uri, r, request_type=RequestType.HTTP_NO_AUTH)
        except Exception as e:
            logging.warning(redirect_msg % e.__class__.__name__)
            sut.set_avoid_http_redirect(True)


def bad_auth_requests(sut: SystemUnderTest):
    headers = {
        'OData-Version': '4.0'
    }
    # request with bad basic auth
    # Keep these invalid basic auth attempts to a minimum. Some services will
    # block clients after a number of failed attempts.
    # e.g. "Login attempt alert for rfpv66af from 192.168.1.101 using REDFISH,
    #       IP will be blocked for 600 seconds."
    uri = sut.sessions_uri
    h = headers.copy()
    r = sut.get(uri, headers=h, auth=(acct.new_username(set()), acct.new_password(sut)),
                     no_session=True)
    sut.add_response(uri, r, request_type=RequestType.BAD_AUTH)
    # request with bad auth token
    token = 'rfpv%012x' % random.randrange(2 ** 48)  # ex: 'rfpv9e40b1f54c8a'
    sut.add_priv_info(token)
    uri = '/redfish/v1/RPVfoobar'
    h = headers.copy()
    h.update({'X-Auth-Token': token})
    r = sut.get(uri, headers=h, no_session=True)
    sut.add_response(uri, r, request_type=RequestType.BAD_AUTH)


def read_uris_no_auth(sut: SystemUnderTest, session):
    for uri in sut.get_all_uris():
        response = sut.get(uri, session=session)
        sut.add_response(uri, response, request_type=RequestType.NO_AUTH)
