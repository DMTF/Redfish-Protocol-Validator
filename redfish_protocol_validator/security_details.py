# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

from base64 import b64decode
import socket
import ssl
from urllib.parse import urlparse

import requests
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5280
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from redfish_protocol_validator import sessions
from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, RequestType, ResourceType, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest


class Tls11HttpAdapter(HTTPAdapter):
    """Transport adapter that requires TLS v1.1 or later."""
    def init_poolmanager(self, connections, maxsize, block=False,
                         **pool_kwargs):
        # allow only TLS 1.1 and later
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=ctx)


def success_response(response, method, uri):
    if response is None:
        return Result.NOT_TESTED, 'No response found for %s request to %s' % (
            method, uri)
    elif response.ok:
        return Result.PASS, 'Test passed'
    else:
        return Result.FAIL, '%s request to %s returned status code %s' % (
            method, uri, response.status_code)


def test_tls_1_1(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_TLS_1_1."""
    session = requests.Session()
    session.mount(sut.rhost, Tls11HttpAdapter())
    session.auth = (sut.username, sut.password)
    session.verify = sut.verify
    uri = '/redfish/v1/'
    status = ''
    try:
        response = session.get(sut.rhost + uri)
        status = response.status_code
        result = Result.PASS
        msg = 'Test passed'
    except Exception as e:
        result = Result.FAIL
        msg = ('Unable to connect to %s using TLS v1.1 or later: %s %s' %
               (sut.rhost, e.__class__.__name__, str(e)))
    sut.log(result, 'GET', status, uri, Assertion.SEC_TLS_1_1, msg)


def test_default_cert_replacement(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_DEFAULT_CERT_REPLACE."""
    if not sut.get_certs():
        msg = 'No certificates found on the service'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SEC_DEFAULT_CERT_REPLACE, msg)
        return

    if sut.certificate_service_uri is not None:
        response = sut.get_response('GET', sut.certificate_service_uri)
        if response.ok:
            data = response.json()
            if ('Actions' in data and '#CertificateService.ReplaceCertificate'
                    in data['Actions']):
                sut.log(Result.PASS, 'GET', response.status_code,
                        sut.certificate_service_uri,
                        Assertion.SEC_DEFAULT_CERT_REPLACE, 'Test passed')
                return

    for uri in sut.get_certs().keys():
        response = sut.get_response('GET', uri)
        if response.ok:
            headers = response.headers
            if 'Allow' in headers:
                methods = [m.strip() for m in headers.get('Allow').split(',')]
                if 'POST' not in methods:
                    msg = ('No ReplaceCertificate Action found in '
                           'CertificateService and POST method not allowed '
                           'for certificate collection %s' % uri)
                    sut.log(Result.FAIL, 'GET', response.status_code, uri,
                            Assertion.SEC_DEFAULT_CERT_REPLACE, msg)
                else:
                    sut.log(Result.PASS, 'GET', response.status_code, uri,
                            Assertion.SEC_DEFAULT_CERT_REPLACE, 'Test passed')
            else:
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.SEC_DEFAULT_CERT_REPLACE, 'Test passed')
        else:
            msg = ('GET request to certificate collection %s failed with '
                   'status %s; unable to test assertion for this URI' %
                   (uri, response.status_code))
            sut.log(Result.NOT_TESTED, 'GET', response.status_code, uri,
                    Assertion.SEC_DEFAULT_CERT_REPLACE, msg)


def test_certs_conform_to_x509v3(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_CERTS_CONFORM_X509V3."""
    rhost = urlparse(sut.rhost)
    if rhost.scheme == 'https':
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(socket.socket(socket.AF_INET),
                                       server_hostname=rhost.hostname)
            port = 443 if rhost.port is None else rhost.port
            conn.connect((rhost.hostname, port))
            bin_cert = conn.getpeercert(binary_form=True)
            cert = decoder.decode(bin_cert, asn1Spec=rfc5280.Certificate())[0]
        except Exception as e:
            msg = ('Exception caught while trying to retrieve and decode '
                   'certificate for %s; exception: %s'
                   % (sut.rhost, str(e)))
            sut.log(Result.FAIL, '', '', '',
                    Assertion.SEC_CERTS_CONFORM_X509V3, msg)
        else:
            version = '<not found>'
            if 'tbsCertificate' in cert:
                if 'version' in cert['tbsCertificate']:
                    version = str(cert['tbsCertificate']['version'])
            if version == 'v3':
                sut.log(Result.PASS, '', '', '',
                        Assertion.SEC_CERTS_CONFORM_X509V3, 'Test passed')
            else:
                msg = ('Server certificate for %s is not X509-v3; the version '
                       'retrieved is %s' % (sut.rhost, version))
                sut.log(Result.FAIL, '', '', '',
                        Assertion.SEC_CERTS_CONFORM_X509V3, msg)
    else:
        msg = ('The scheme for the service at %s is not HTTPS'
               % sut.rhost)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SEC_CERTS_CONFORM_X509V3, msg)


def test_basic_auth_standalone(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_BASIC_AUTH_STANDALONE."""
    response = sut.get_response('GET', sut.sessions_uri,
                                request_type=RequestType.BASIC_AUTH)
    result, msg = success_response(response, 'GET', sut.sessions_uri)
    sut.log(result, 'GET', response.status_code if response else '',
            sut.sessions_uri, Assertion.SEC_BASIC_AUTH_STANDALONE, msg)


def test_both_auth_types(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_BOTH_AUTH_TYPES."""
    ba_response = sut.get_response('GET', sut.sessions_uri,
                                   request_type=RequestType.BASIC_AUTH)
    sess_response = sut.get_response('GET', sut.sessions_uri)
    ba_result, ba_msg = success_response(ba_response, 'GET', sut.sessions_uri)
    sess_result, sess_msg = success_response(sess_response, 'GET',
                                             sut.sessions_uri)
    if ba_result == Result.PASS and sess_result == Result.PASS:
        sut.log(Result.PASS, 'GET', ba_response.status_code, sut.sessions_uri,
                Assertion.SEC_BOTH_AUTH_TYPES, ba_msg)
    elif ba_result == Result.FAIL or sess_result == Result.FAIL:
        msg = sess_msg if sess_result == Result.FAIL else ba_msg
        st = ba_response.status_code if (
                ba_result == Result.FAIL) else sess_response.status_code
        sut.log(Result.FAIL, 'GET', st, sut.sessions_uri,
                Assertion.SEC_BOTH_AUTH_TYPES, msg)
    else:
        msg = sess_msg if sess_result == Result.NOT_TESTED else ba_msg
        sut.log(Result.NOT_TESTED, 'GET', '', sut.sessions_uri,
                Assertion.SEC_BOTH_AUTH_TYPES, msg)


def test_write_requires_auth(sut: SystemUnderTest):
    """"Perform test for Assertion.SEC_WRITE_REQUIRES_AUTH."""
    for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        for uri, response in sut.get_responses_by_method(
                method, request_type=RequestType.NO_AUTH).items():
            if method == 'POST' and uri == sut.sessions_uri:
                if response.ok:
                    sut.log(Result.PASS, method, response.status_code, uri,
                            Assertion.SEC_WRITE_REQUIRES_AUTH, 'Test passed')
                else:
                    msg = ('%s request to %s with no authentication failed '
                           'with status %s' % (
                               method, uri, response.status_code))
                    sut.log(Result.FAIL, method, response.status_code, uri,
                            Assertion.SEC_WRITE_REQUIRES_AUTH, msg)
            else:
                if response.ok:
                    msg = ('%s request to %s with no authentication succeeded '
                           'with status %s' % (
                               method, uri, response.status_code))
                    sut.log(Result.FAIL, method, response.status_code, uri,
                            Assertion.SEC_WRITE_REQUIRES_AUTH, msg)
                else:
                    sut.log(Result.PASS, method, response.status_code, uri,
                            Assertion.SEC_WRITE_REQUIRES_AUTH, 'Test passed')


def test_read_requires_auth(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_READ_REQUIRES_AUTH."""
    for method in ['GET', 'HEAD']:
        for uri, response in sut.get_responses_by_method(
                method, request_type=RequestType.NO_AUTH).items():
            if uri in ['/redfish', '/redfish/v1', '/redfish/v1/',
                       '/redfish/v1/odata', '/redfish/v1/$metadata']:
                if response.ok:
                    sut.log(Result.PASS, response.request.method,
                            response.status_code, uri,
                            Assertion.SEC_READ_REQUIRES_AUTH, 'Test passed')
                else:
                    msg = ('%s request to %s with no authentication failed '
                           'with status %s' % (response.request.method, uri,
                                               response.status_code))
                    sut.log(Result.FAIL, response.request.method,
                            response.status_code, uri,
                            Assertion.SEC_READ_REQUIRES_AUTH, msg)
            else:
                if response.ok:
                    msg = ('%s request to %s with no authentication succeeded '
                           'with status %s' % (response.request.method, uri,
                                               response.status_code))
                    sut.log(Result.FAIL, response.request.method,
                            response.status_code, uri,
                            Assertion.SEC_READ_REQUIRES_AUTH, msg)
                else:
                    sut.log(Result.PASS, response.request.method,
                            response.status_code, uri,
                            Assertion.SEC_READ_REQUIRES_AUTH, 'Test passed')


def test_redirect_enforces_target_privs(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS."""
    uri = sut.sessions_uri
    redirect_found = False
    response = sut.get_response('GET', uri,
                                request_type=RequestType.HTTP_NO_AUTH)
    if response is not None:
        if len(response.history):
            # HTTP redirect occurred if there is a response.history
            # check the final status and expect a 401
            redirect_found = True
            if response.status_code == requests.codes.UNAUTHORIZED:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS,
                        'Test passed')
            else:
                msg = ('After HTTP redirect from %s to %s, response status '
                       'was %s, expected 401' % (
                        response.history[0].url, response.url,
                        response.status_code))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS, msg)
    if not redirect_found:
        msg = 'No response found with an HTTP redirect'
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.SEC_REDIRECT_ENFORCES_TARGET_PRIVS, msg)


def test_redirect_to_https(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_REDIRECT_TO_HTTPS."""
    uri = '/redfish/v1/'
    redirect_found = False
    response = sut.get_response('GET', uri,
                                request_type=RequestType.HTTP_NO_AUTH)
    if response is not None:
        if len(response.history):
            # HTTP redirect occurred if there is a response.history
            # check the final status and expect a 200
            redirect_found = True
            if response.status_code == requests.codes.OK:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_REDIRECT_TO_HTTPS,
                        'Test passed')
            else:
                msg = ('After HTTP redirect from %s to %s, response status '
                       'was %s, expected 200' % (
                           response.history[0].url, response.url,
                           response.status_code))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_REDIRECT_TO_HTTPS, msg)
    if not redirect_found:
        msg = 'No response found with an HTTP redirect'
        sut.log(Result.NOT_TESTED, 'GET', '', uri,
                Assertion.SEC_REDIRECT_TO_HTTPS, msg)


def test_no_priv_info_in_msgs(sut: SystemUnderTest):
    """"Perform test for Assertion.SEC_NO_PRIV_INFO_IN_MSGS."""
    for uri, response in sut.get_all_responses(
            request_type=RequestType.BAD_AUTH):
        if not response.ok:
            pi_found = None
            if response.text:
                for pi in sut.priv_info:
                    if pi in response.text:
                        pi_found = pi
                        break
            if pi_found:
                if pi_found == sut.password:
                    # do not include the service password in the report
                    pi_found = '*' * len(pi_found)
                msg = ('%s request to %s with wrong credentials returned '
                       'status %s but extended error message may have '
                       'provided privileged information ("%s")' % (
                           response.request.method, uri, response.status_code,
                           pi_found))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_NO_PRIV_INFO_IN_MSGS, msg)
            else:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_NO_PRIV_INFO_IN_MSGS, 'Test passed')


def test_headers_auth_before_etag(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_HEADERS_FIRST."""
    headers = {
        'OData-Version': '4.0'
    }
    responses = sut.get_responses_by_method(
        'GET', resource_type=ResourceType.MANAGER_ACCOUNT)
    etag_found = False
    for uri, response in responses.items():
        if response.ok:
            etag = response.headers.get('ETag')
            if etag:
                etag_found = True
                # make request w/ no auth and If-None-Match header
                h = headers.copy()
                h.update({'If-None-Match': etag})
                r = requests.get(sut.rhost + uri, headers=h,
                                 verify=sut.verify)
                if r.status_code == requests.codes.UNAUTHORIZED:
                    sut.log(Result.PASS, 'GET', r.status_code, uri,
                            Assertion.SEC_HEADERS_FIRST, 'Test passed')
                elif r.status_code == requests.codes.NOT_MODIFIED:
                    msg = ('%s request with If-None-Match header to %s with '
                           'bad authentication returned status %s; expected '
                           'status %s' % ('GET', uri, r.status_code,
                                          requests.codes.UNAUTHORIZED))
                    sut.log(Result.FAIL, 'GET', r.status_code, uri,
                            Assertion.SEC_HEADERS_FIRST, msg)
                else:
                    msg = ('%s request with If-None-Match header to %s with '
                           'bad authentication returned unexpected status %s; '
                           'expected status %s' % (
                               'GET', uri, r.status_code,
                               requests.codes.UNAUTHORIZED))
                    sut.log(Result.NOT_TESTED, 'GET', r.status_code,
                            uri, Assertion.SEC_HEADERS_FIRST, msg)
    if not etag_found:
        msg = ('No ManagerAccount GET responses found with an ETag header; '
               'unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'GET', '', '', Assertion.SEC_HEADERS_FIRST,
                msg)
        pass


def test_no_auth_cookies(sut):
    """Perform test for Assertion.SEC_NO_AUTH_COOKIES."""
    response_found = False
    for uri, response in sut.get_responses_by_method(
            'POST').items():
        if uri == sut.sessions_uri:
            if response.ok:
                response_found = True
                set_cookie = response.headers.get('Set-Cookie')
                if set_cookie:
                    msg = ('Service MAY support HTTP cookies to authenticate '
                           'activity; Set-Cookie header found in %s response '
                           'to %s (Set-Cookie: %s)' % (
                               'POST', uri, set_cookie))
                    sut.log(Result.WARN, 'POST', response.status_code, uri,
                            Assertion.SEC_NO_AUTH_COOKIES, msg)
                else:
                    sut.log(Result.PASS, 'POST', response.status_code, uri,
                            Assertion.SEC_NO_AUTH_COOKIES, 'Test passed')
    if not response_found:
        msg = ('No successful POST response to Sessions URI found; unable to '
               'test this assertion')
        sut.log(Result.NOT_TESTED, 'POST', '', sut.sessions_uri,
                Assertion.SEC_NO_AUTH_COOKIES, msg)


def test_support_basic_auth(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_SUPPORT_BASIC_AUTH"""
    for uri, response in sut.get_all_responses(
            request_type=RequestType.BASIC_AUTH):
        if response.ok:
            sut.log(Result.PASS, response.request.method,
                    response.status_code, uri,
                    Assertion.SEC_SUPPORT_BASIC_AUTH, 'Test passed')
        else:
            msg = ('%s request to %s using basic auth failed with status %s' %
                   (response.request.method, uri, response.status_code))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, uri,
                    Assertion.SEC_SUPPORT_BASIC_AUTH, msg)


def test_basic_auth_over_https(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_BASIC_AUTH_OVER_HTTPS"""
    for uri, response in sut.get_all_responses(
            request_type=RequestType.HTTP_BASIC_AUTH):
        if response.ok:
            if response.url.startswith('https:'):
                # redirected to HTTPS
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_BASIC_AUTH_OVER_HTTPS, 'Test passed')
            else:
                # request success trying to use HTTP with basic auth
                msg = ('%s request to %s using basic auth over HTTP succeeded '
                       'with status %s but did not redirect to HTTPS; final '
                       'URL was %s' %
                       (response.request.method, uri, response.status_code,
                        response.url))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_BASIC_AUTH_OVER_HTTPS, msg)
        else:
            # request failed trying to use HTTP with basic auth
            sut.log(Result.PASS, response.request.method,
                    response.status_code, uri,
                    Assertion.SEC_BASIC_AUTH_OVER_HTTPS, 'Test passed')


def test_require_login_sessions(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_REQUIRE_LOGIN_SESSIONS"""
    response = sut.get_response('POST', sut.sessions_uri)
    if response is not None:
        if response.ok:
            location = response.headers.get('Location')
            token = response.headers.get('X-Auth-Token')
            if location and token:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, sut.sessions_uri,
                        Assertion.SEC_REQUIRE_LOGIN_SESSIONS, 'Test passed')
            else:
                if not location and not token:
                    h = 'Location and X-Auth-Token headers were'
                elif not location:
                    h = 'Location header was'
                else:
                    h = 'X-Auth-Token header was'
                msg = ('POST request to %s succeeded with status %s, but the '
                       'required %s not returned in the response' % (
                        sut.sessions_uri, response.status_code, h))
                sut.log(Result.FAIL, response.request.method,
                        response.status_code, sut.sessions_uri,
                        Assertion.SEC_REQUIRE_LOGIN_SESSIONS, msg)
        else:
            msg = ('POST request to %s to create a login session failed with '
                   'status %s' % (sut.sessions_uri, response.status_code))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, sut.sessions_uri,
                    Assertion.SEC_REQUIRE_LOGIN_SESSIONS, msg)


def test_sessions_uri_location(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_SESSIONS_URI_LOCATION."""
    sessions_uri1, sessions_uri2 = None, None
    response1 = sut.get_response('GET', '/redfish/v1/')
    if response1.ok:
        data = response1.json()
        if 'Links' in data and 'Sessions' in data['Links']:
            sessions_uri1 = data['Links']['Sessions']['@odata.id']
        if 'SessionService' in data:
            uri = data['SessionService']['@odata.id']
            response2 = sut.get_response('GET', uri)
            if response2.ok:
                data = response2.json()
                if 'Sessions' in data:
                    sessions_uri2 = data['Sessions']['@odata.id']
        if sessions_uri1 and sessions_uri2:
            if sessions_uri1 == sessions_uri2:
                sut.log(Result.PASS, 'GET', response1.status_code,
                        sessions_uri1, Assertion.SEC_SESSIONS_URI_LOCATION,
                        'Test passed')
            else:
                msg = ('Sessions URI from ServiceRoot Links property (%s) not '
                       'equal to URI from SessionService (%s)' % (
                           sessions_uri1, sessions_uri2))
                sut.log(Result.FAIL, 'GET', response1.status_code,
                        sessions_uri1, Assertion.SEC_SESSIONS_URI_LOCATION,
                        msg)
        elif sessions_uri1 is None:
            msg = 'Sessions URI from ServiceRoot Links property not found'
            sut.log(Result.FAIL, 'GET', response1.status_code, '',
                    Assertion.SEC_SESSIONS_URI_LOCATION, msg)
        else:
            msg = 'Sessions URI from SessionService resource not found'
            sut.log(Result.NOT_TESTED, 'GET', '', '',
                    Assertion.SEC_SESSIONS_URI_LOCATION, msg)


def test_session_post_response(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_SESSION_POST_RESPONSE."""
    response = sut.get_response('POST', sut.sessions_uri)
    failed = False
    if response.ok:
        for header in ['X-Auth-Token', 'Location']:
            if header not in response.headers:
                failed = True
                msg = ('Response for POST to %s did not contain required '
                       '%s header' % (sut.sessions_uri, header))
                sut.log(Result.FAIL, 'POST', response.status_code,
                        sut.sessions_uri, Assertion.SEC_SESSION_POST_RESPONSE,
                        msg)
        if response.status_code == requests.codes.CREATED:
            data = response.json()
            missing_props = []
            for prop in ['@odata.id', '@odata.type', 'Id', 'Name', 'UserName']:
                if prop not in data:
                    missing_props.append(prop)
            if missing_props:
                failed = True
                msg = ('Response payload for POST to %s did not contain full '
                       'representation of the new session resource; missing '
                       'properties: %s ' % (sut.sessions_uri, missing_props))
                sut.log(Result.FAIL, 'POST', response.status_code,
                        sut.sessions_uri, Assertion.SEC_SESSION_POST_RESPONSE,
                        msg)
        else:
            failed = True
            msg = ('Response for POST to %s returned status %s, expected '
                   'status %s in order to return full representation of the '
                   'new session resource' %
                   (sut.sessions_uri, response.status_code,
                    requests.codes.CREATED))
            sut.log(Result.FAIL, 'POST', response.status_code,
                    sut.sessions_uri, Assertion.SEC_SESSION_POST_RESPONSE,
                    msg)
        if not failed:
            sut.log(Result.PASS, 'POST', response.status_code,
                    sut.sessions_uri, Assertion.SEC_SESSION_POST_RESPONSE,
                    'Test passed')
    else:
        msg = ('Response for POST to %s was not successful; cannot test this '
               'assertion' % sut.sessions_uri)
        sut.log(Result.NOT_TESTED, 'POST', response.status_code,
                sut.sessions_uri, Assertion.SEC_SESSION_POST_RESPONSE, msg)


def test_session_create_https_only(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_SESSION_CREATE_HTTPS_ONLY."""
    if sut.scheme == 'https':
        payload = {
            'UserName': sut.username,
            'Password': sut.password
        }
        headers = {
            'OData-Version': '4.0'
        }
        http_rhost = 'http' + sut.rhost[5:]
        try:
            response = requests.post(
                http_rhost + sut.sessions_uri, json=payload, headers=headers,
                verify=sut.verify)
        except Exception as e:
            sut.set_avoid_http_redirect(True)
            msg = ('Caught %s; unable to test this assertion' %
                   e.__class__.__name__)
            sut.log(Result.NOT_TESTED, 'POST', '',
                    sut.sessions_uri, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                    msg)
            return
    elif sut.scheme == 'http':
        # scheme was already HTTP; just fetch response already made
        response = sut.get_response('POST', sut.sessions_uri)
    else:
        msg = ('Unexpected scheme (%s) for remote host %s found, '
               'expected http or https; skipping http request' %
               (sut.scheme, sut.rhost))
        sut.log(Result.NOT_TESTED, 'POST', '',
                sut.sessions_uri, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                msg)
        return
    if response.ok:
        if response.url.startswith('https:'):
            # HTTP redirected to HTTPS
            sut.log(Result.PASS, 'POST', response.status_code,
                    sut.sessions_uri, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                    'Test passed')
        else:
            # request succeeded when going to HTTP; should fail in this case
            msg = ('%s request to %s using HTTP scheme succeeded with status '
                   '%s; should fail or redirect to HTTPS; final URL %s' %
                   ('POST', sut.sessions_uri, response.status_code,
                    response.url))
            sut.log(Result.FAIL, 'POST', response.status_code,
                    sut.sessions_uri, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                    msg)
    else:
        # request failed when going to HTTP; this is OK
        sut.log(Result.PASS, 'POST', response.status_code,
                sut.sessions_uri, Assertion.SEC_SESSION_CREATE_HTTPS_ONLY,
                'Test passed')


def test_session_termination_side_effects(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS."""
    if not sut.server_sent_event_uri:
        msg = 'No ServerSentEventUri available; unable to test this assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS, msg)
        return

    # create a session
    new_session_uri, token = sessions.create_session(sut)
    if new_session_uri and token:
        session = requests.Session()
        session.headers.update({'X-Auth-Token': token})
        session.verify = sut.verify
        # open the SSE stream
        response = None
        exc_name = ''
        try:
            response = session.get(sut.rhost + sut.server_sent_event_uri,
                                   stream=True)
        except Exception as e:
            exc_name = e.__class__.__name__
        if response is None:
            msg = ('Caught %s while opening SSE stream; unable to test this '
                   'assertion' % exc_name)
            sut.log(Result.NOT_TESTED, 'GET', '', sut.server_sent_event_uri,
                    Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS, msg)
        elif response.ok:
            # delete the session
            r = session.delete(sut.rhost + new_session_uri)
            if r.ok:
                # read from the SSE stream
                try:
                    lines = response.iter_lines()
                    for _ in lines:
                        sut.log(Result.PASS, 'GET', response.status_code,
                                sut.server_sent_event_uri,
                                Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                                'Test passed')
                        break
                    else:
                        msg = ('Unable to read from ServerSentEventUri stream '
                               '%s after deleting session' %
                               sut.server_sent_event_uri)
                        sut.log(Result.FAIL, 'GET', '',
                                sut.server_sent_event_uri,
                                Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                                msg)
                except Exception as e:
                    msg = ('Exception raised while trying to read from '
                           'ServerSentEventUri stream %s after deleting '
                           'session; exception: %s' %
                           (sut.server_sent_event_uri, str(e)))
                    sut.log(Result.FAIL, 'GET', '',
                            sut.server_sent_event_uri,
                            Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS,
                            msg)
            else:
                msg = ('Deleting session %s failed with status %s; unable to '
                       'test this assertion' %
                       (new_session_uri, r.status_code))
                sut.log(Result.NOT_TESTED, 'DELETE', r.status_code,
                        new_session_uri,
                        Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS, msg)
            # close the SSE stream
            if response is not None:
                response.close()
        else:
            msg = ('Opening ServerSentEventUri %s failed with status %s; '
                   'unable to test this assertion' %
                   (sut.server_sent_event_uri, response.status_code))
            sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                    sut.server_sent_event_uri,
                    Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS, msg)
    else:
        msg = 'Failed to create session; unable to test this assertion'
        sut.log(Result.NOT_TESTED, 'POST', '', sut.sessions_uri,
                Assertion.SEC_SESSION_TERMINATION_SIDE_EFFECTS, msg)


def test_accounts_support_etags(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS."""
    responses = sut.get_responses_by_method(
        'PATCH', resource_type=ResourceType.MANAGER_ACCOUNT,
        request_type=RequestType.BAD_ETAG)
    found_response = False
    for uri, response in responses.items():
        found_response = True
        if response.ok:
            msg = ('%s request to account URI %s with invalid If-Match header '
                   'succeeded; expected it to fail with status %s'
                   % (response.request.method, uri,
                      requests.codes.PRECONDITION_FAILED))
            sut.log(Result.FAIL, response.request.method,
                    response.status_code, uri,
                    Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)
        else:
            if response.status_code == requests.codes.PRECONDITION_FAILED:
                sut.log(Result.PASS, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, 'Test passed')
            else:
                msg = ('%s request to account URI %s with invalid If-Match '
                       'header failed with status %s; expected it to fail '
                       'with status %s; extended error: %s' %
                       (response.request.method, uri, response.status_code,
                        requests.codes.PRECONDITION_FAILED,
                        utils.get_extended_error(response)))
                sut.log(Result.WARN, response.request.method,
                        response.status_code, uri,
                        Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)
    if not found_response:
        msg = ('No PATCH request to account resource with invalid If-Match '
               'header found; unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'PATCH', '', '',
                Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)


def test_password_change_required(sut: SystemUnderTest):
    """Perform tests for Assertion.PasswordChangeRequired."""
    # check the POST to create session (should succeed)
    # Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN
    response = sut.get_response('POST', sut.sessions_uri,
                                request_type=RequestType.PWD_CHANGE_REQUIRED)
    if response is None:
        msg = ('PasswordChangeRequired property not found in account '
               'resource; unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'POST', '', sut.sessions_uri,
                Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN, msg)
    else:
        if response.ok:
            data = response.json()
            keys = utils.get_extended_info_message_keys(data)
            if 'PasswordChangeRequired' in keys:
                sut.log(Result.PASS, 'POST', response.status_code,
                        sut.sessions_uri,
                        Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN,
                        'Test passed')
            else:
                msg = ('Response from POST to %s did not contain '
                       'PasswordChangeRequired message from the Base Message '
                       'Registry' % sut.sessions_uri)
                sut.log(Result.FAIL, 'POST', response.status_code,
                        sut.sessions_uri,
                        Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN, msg)
        else:
            msg = ('POST request to %s using account with '
                   'PasswordChangeRequired set failed with status %s' %
                   (sut.sessions_uri, response.status_code))
            sut.log(Result.FAIL, 'POST', response.status_code,
                    sut.sessions_uri,
                    Assertion.SEC_PWD_CHANGE_REQ_ALLOW_SESSION_LOGIN, msg)
    # check the GET of the account (should succeed)
    # Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT
    responses = sut.get_responses_by_method(
        'GET', resource_type=ResourceType.MANAGER_ACCOUNT,
        request_type=RequestType.PWD_CHANGE_REQUIRED)
    account_uri = None
    if responses:
        for uri, response in responses.items():
            account_uri = uri
            if response.ok:
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT,
                        'Test passed')
            else:
                msg = ('GET request to %s using account with '
                       'PasswordChangeRequired set failed with status %s' %
                       (uri, response.status_code))
                sut.log(Result.FAIL, 'GET', response.status_code, uri,
                        Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT, msg)
            break
    else:
        msg = ('No GET request to account URI found using account with '
               'PasswordChangeRequired set; unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'GET', '', '',
                Assertion.SEC_PWD_CHANGE_REQ_ALLOW_GET_ACCOUNT, msg)
    # check GET of protected resource (should fail with 403)
    # Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS
    response = sut.get_response('GET', sut.sessions_uri,
                                request_type=RequestType.PWD_CHANGE_REQUIRED)
    if response is None:
        msg = ('No GET request to %s found using account with '
               'PasswordChangeRequired set; unable to test this assertion'
               % sut.sessions_uri)
        sut.log(Result.NOT_TESTED, 'GET', '', sut.sessions_uri,
                Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS, msg)
    else:
        if response.status_code == requests.codes.FORBIDDEN:
            data = response.json()
            keys = utils.get_extended_info_message_keys(data)
            if 'PasswordChangeRequired' in keys:
                sut.log(Result.PASS, 'GET', response.status_code,
                        sut.sessions_uri,
                        Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS,
                        'Test passed')
            else:
                msg = ('Response from GET to %s did not contain '
                       'PasswordChangeRequired message from the Base Message '
                       'Registry' % sut.sessions_uri)
                sut.log(Result.FAIL, 'GET', response.status_code,
                        sut.sessions_uri,
                        Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS, msg)
        else:
            msg = ('GET request to %s using account with '
                   'PasswordChangeRequired set responded with status %s; '
                   'expected it to fail with status 403' %
                   (sut.sessions_uri, response.status_code))
            sut.log(Result.FAIL, 'GET', response.status_code, sut.sessions_uri,
                    Assertion.SEC_PWD_CHANGE_REQ_DISALLOW_ALL_OTHERS, msg)
    # check PATCH to change password
    # Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD
    if account_uri:
        response = sut.get_response(
            'PATCH', account_uri, request_type=RequestType.PWD_CHANGE_REQUIRED)
        if response is None:
            msg = ('No PATCH request to %s found using account with '
                   'PasswordChangeRequired set; unable to test this assertion'
                   % account_uri)
            sut.log(Result.NOT_TESTED, 'PATCH', '', account_uri,
                    Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD, msg)
        else:
            if response.ok:
                data = response.json()
                if ('PasswordChangeRequired' in data and
                        data['PasswordChangeRequired'] is False):
                    sut.log(Result.PASS, 'PATCH', response.status_code,
                            account_uri,
                            Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
                            'Test passed')
                else:
                    msg = ('Password change to %s succeeded with status %s, '
                           'but response payload did not have '
                           'PasswordChangeRequired property set to false' %
                           (response.status_code, account_uri))
                    sut.log(Result.FAIL, 'PATCH', response.status_code,
                            account_uri,
                            Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
                            msg)
            else:
                msg = ('Password change to %s failed with status %s; '
                       'expected it to succeed' %
                       (account_uri, response.status_code))
                sut.log(Result.FAIL, 'PATCH', response.status_code,
                        account_uri,
                        Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD,
                        msg)
    else:
        msg = ('No PATCH request to account URI found using account with '
               'PasswordChangeRequired set; unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'PATCH', '', '',
                Assertion.SEC_PWD_CHANGE_REQ_ALLOW_PATCH_PASSWORD, msg)


def test_priv_one_role_per_user(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_PRIV_ONE_ROLE_PRE_USER."""
    for uri, response in sut.get_responses_by_method(
            'GET', resource_type=ResourceType.MANAGER_ACCOUNT).items():
        if response.ok:
            data = response.json()
            role = data.get('RoleId')
            if role is not None:
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.SEC_PRIV_ONE_ROLE_PRE_USER,
                        'Test passed')
            else:
                msg = ('Account URI %s does not have a RoleId property' % uri)
                sut.log(Result.FAIL, 'GET', response.status_code, uri,
                        Assertion.SEC_PRIV_ONE_ROLE_PRE_USER, msg)


def test_priv_support_predefined_roles(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES."""
    role_map = {
        'Administrator': {
            'privs': {'Login', 'ConfigureManager', 'ConfigureUsers',
                      'ConfigureComponents', 'ConfigureSelf'},
            'found': False
        },
        'Operator': {
            'privs': {'Login', 'ConfigureComponents', 'ConfigureSelf'},
            'found': False
        },
        'ReadOnly': {
            'privs': {'Login', 'ConfigureSelf'},
            'found': False
        }
    }
    for uri, response in sut.get_responses_by_method(
            'GET', resource_type=ResourceType.ROLE).items():
        if response.ok:
            data = response.json()
            role = data.get('Id')
            if role in role_map:
                role_map[role]['found'] = True
                privs = set(data.get('AssignedPrivileges', []))
                if privs == role_map[role]['privs']:
                    sut.log(Result.PASS, 'GET', response.status_code, uri,
                            Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES,
                            'Test passed')
                else:
                    msg = ('Predefined role %s assigned privileges found: %s; '
                           'expected: %s' % (
                            role, privs, role_map[role]['privs']))
                    sut.log(Result.FAIL, 'GET', response.status_code, uri,
                            Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES, msg)
    for role in role_map.keys():
        if not role_map[role]['found']:
            msg = ('Predefined role %s not found' % role)
            sut.log(Result.FAIL, 'GET', '', '',
                    Assertion.SEC_PRIV_SUPPORT_PREDEFINED_ROLES, msg)


def test_priv_predefined_roles_not_modifiable(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE."""
    read_only_found = False
    uri = None
    data = {}
    role = 'ReadOnly'
    test_priv = ['Login', 'ConfigureManager', 'ConfigureUsers',
                 'ConfigureComponents', 'ConfigureSelf']
    # locate the ReadOnly role
    for uri, response in sut.get_responses_by_method(
            'GET', resource_type=ResourceType.ROLE).items():
        if response.ok:
            data = response.json()
            if data.get('Id') == role:
                read_only_found = True
                break
    if read_only_found:
        # Save the current privileges in case the PATCH is accepted
        privs = data.get('AssignedPrivileges')
        if privs:
            # PATCH the test privileges
            payload = {'AssignedPrivileges': test_priv}
            headers = utils.get_etag_header(sut, sut.session, uri)
            response = sut.session.patch(sut.rhost + uri, json=payload,
                                         headers=headers)
            if response.ok:
                msg = ('PATCH request to %s to modify the AssignedPrivileges '
                       'of predefined role %s succeeded with status %s; '
                       'expected it to fail' %
                       (uri, role, response.status_code))
                sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                        Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
                        msg)
                # PATCH succeeded unexpectedly; try to PATCH it back
                r = sut.session.get(sut.rhost + uri)
                if r.ok:
                    payload = {'AssignedPrivileges': privs}
                    etag = r.headers.get('ETag')
                    headers = {'If-Match': etag} if etag else {}
                    sut.session.patch(sut.rhost + uri, json=payload,
                                      headers=headers)
            else:
                sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                        Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE,
                        'Test passed')
        else:
            msg = ('No AssignedPrivileges found in role %s; unable to '
                   'test this assertion' % role)
            sut.log(Result.NOT_TESTED, 'PATCH', '', uri,
                    Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE, msg)
    else:
        msg = ('Predefined role %s not found; unable to test this assertion'
               % role)
        sut.log(Result.NOT_TESTED, 'PATCH', '', '',
                Assertion.SEC_PRIV_PREDEFINED_ROLE_NOT_MODIFIABLE, msg)


def test_priv_roles_assigned_at_account_create(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE."""
    for uri, response in sut.get_responses_by_method(
            'GET', resource_type=ResourceType.MANAGER_ACCOUNT).items():
        if response.ok:
            data = response.json()
            username = data.get('UserName', '')
            if username.startswith('rfpv'):
                role = data.get('RoleId')
                if role is not None:
                    sut.log(Result.PASS, 'GET', response.status_code, uri,
                            Assertion.SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE,
                            'Test passed')
                else:
                    msg = ('Newly created account with username %s does not '
                           'have a RoleId property' % username)
                    sut.log(Result.FAIL, 'GET', response.status_code, uri,
                            Assertion.SEC_PRIV_ROLE_ASSIGNED_AT_ACCOUNT_CREATE,
                            msg)


def test_priv_operation_to_priv_mapping(sut: SystemUnderTest):
    """Perform test for Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING."""
    response_found = False
    for uri, response in sut.get_responses_by_method(
            'PATCH', resource_type=ResourceType.MANAGER_ACCOUNT,
            request_type=RequestType.MODIFY_OTHER).items():
        response_found = True
        auth = response.request.headers.get('Authorization')
        user = ''
        if auth and 'Basic' in auth:
            user = (b64decode(auth.strip().split()[-1]).decode('utf-8')
                    .split(':', maxsplit=1)[0])
        if response.ok:
            msg = ('PATCH request to account %s using credentials of other '
                   'user %s succeeded with status %s; expected it to fail '
                   'with status %s' % (uri, user, response.status_code,
                                       requests.codes.UNAUTHORIZED))
            sut.log(Result.FAIL, 'PATCH', response.status_code, uri,
                    Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
                    msg)
        else:
            if response.status_code == requests.codes.FORBIDDEN or response.status_code == requests.codes.NOT_FOUND:
                sut.log(Result.PASS, 'PATCH', response.status_code, uri,
                        Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
                        'Test passed')
            else:
                msg = ('PATCH request to account %s using credentials of '
                       'other user %s failed with status %s, but expected it '
                       'to fail with status %s or %s; extended error: %s' % (
                        uri, user, response.status_code,
                        requests.codes.FORBIDDEN,
                        requests.codes.NOT_FOUND,
                        utils.get_extended_error(response)))
                sut.log(Result.WARN, 'PATCH', response.status_code, uri,
                        Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
                        msg)
    if not response_found:
        msg = ('No response found attempting to PATCH an account using the '
               'credentials of other user; unable to test this assertion')
        sut.log(Result.NOT_TESTED, 'PATCH', '', '',
                Assertion.SEC_PRIV_OPERATION_TO_PRIV_MAPPING,
                msg)


def test_authentication(sut: SystemUnderTest):
    """Perform authentication tests"""
    test_basic_auth_standalone(sut)
    test_both_auth_types(sut)
    test_write_requires_auth(sut)
    test_read_requires_auth(sut)
    test_redirect_enforces_target_privs(sut)
    test_redirect_to_https(sut)
    test_no_priv_info_in_msgs(sut)
    test_headers_auth_before_etag(sut)
    test_no_auth_cookies(sut)
    test_support_basic_auth(sut)
    test_basic_auth_over_https(sut)
    test_require_login_sessions(sut)
    test_sessions_uri_location(sut)
    test_session_post_response(sut)
    if not sut.avoid_http_redirect:
        test_session_create_https_only(sut)
    test_session_termination_side_effects(sut)
    test_accounts_support_etags(sut)
    test_password_change_required(sut)
    test_priv_one_role_per_user(sut)
    test_priv_support_predefined_roles(sut)
    test_priv_predefined_roles_not_modifiable(sut)
    test_priv_roles_assigned_at_account_create(sut)
    test_priv_operation_to_priv_mapping(sut)


def test_protocols(sut: SystemUnderTest):
    """Perform security protocol tests"""
    test_tls_1_1(sut)
    test_default_cert_replacement(sut)
    test_certs_conform_to_x509v3(sut)


def test_security_details(sut: SystemUnderTest):
    """Perform tests from the 'Protocol details' section of the spec."""
    test_authentication(sut)
    test_protocols(sut)
