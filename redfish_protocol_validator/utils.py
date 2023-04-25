# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import http.client
import io
import logging
import math
import re
import socket
import time
from collections import namedtuple

import colorama
import requests
import sseclient

from redfish_protocol_validator.constants import Result, SSDP_REDFISH

_color_map = {
        Result.PASS: (colorama.Fore.GREEN, colorama.Style.RESET_ALL),
        Result.WARN: (colorama.Fore.YELLOW, colorama.Style.RESET_ALL),
        Result.FAIL: (colorama.Fore.RED, colorama.Style.RESET_ALL),
        Result.NOT_TESTED: ('', ''),
    }


def get_response_media_type(response):
    header = response.headers.get('Content-Type', '')
    return header.split(';', 1)[0].strip().lower()


def get_response_media_type_charset(response):
    header = response.headers.get('Content-Type', '')
    if ';' in header:
        return header.split(';', 1)[1].strip().lower()


def get_etag_header(sut, session, uri):
    response = session.get(sut.rhost + uri)
    etag = None
    if response.ok:
        etag = response.headers.get('ETag')
    return {'If-Match': etag} if etag else {}


def get_response_etag(response: requests.Response):
    etag = None
    if response.ok:
        etag = response.headers.get('ETag')
        if not etag:
            if get_response_media_type(response) == 'application/json':
                data = response.json()
                etag = data.get('@odata.etag')
    return etag


def get_extended_error(response: requests.Response):
    message = ''
    try:
        data = response.json()
        if 'error' in data:
            error = data['error']
            if 'message' in error:
                message = error['message']
            elif 'code' in error:
                message = error['code']
            ext_info = error.get('@Message.ExtendedInfo', [])
            if isinstance(ext_info, list) and len(ext_info) > 0:
                if 'Message' in ext_info[0]:
                    message = ext_info[0]['Message']
                elif 'MessageId' in ext_info[0]:
                    message = ext_info[0]['MessageId']
    except Exception:
        pass
    return message


def get_extended_info_message_keys(body: dict):
    data = []
    if 'error' in body and '@Message.ExtendedInfo' in body['error']:
        data = body['error']['@Message.ExtendedInfo']
    elif '@Message.ExtendedInfo' in body:
        data = body['@Message.ExtendedInfo']
    return {d['MessageId'].split('.')[-1] for d in data if 'MessageId' in d}


def is_text_in_extended_error(text: str, body: dict):
    data = []
    if 'error' in body and '@Message.ExtendedInfo' in body['error']:
        data = body['error']['@Message.ExtendedInfo']
    elif 'error' in body and 'message' in body['error']:
        # Simple error message; just inspect the message string
        if text in body['error']['message']:
            return True
    elif '@Message.ExtendedInfo' in body:
        data = body['@Message.ExtendedInfo']
    for d in data:
        if (text in d.get('Message', '') or text in d.get('Resolution', '')
                or text in d.get('MessageArgs', '')):
            return True
    return False


def get_sse_stream(sut):
    response = None
    event_dest_uri = None
    subs = set()
    try:
        # get the "before" set of EventDestination URIs
        if sut.subscriptions_uri:
            r = sut.session.get(sut.rhost + sut.subscriptions_uri)
            if r.status_code == requests.codes.OK:
                data = r.json()
                subs = set([m.get('@odata.id') for m in data.get('Members', [])
                            if '@odata.id' in m])

        if sut.server_sent_event_uri:
            response = sut.session.get(sut.rhost + sut.server_sent_event_uri,
                                       stream=True)
        if response is not None and response.ok and sut.subscriptions_uri:
            # get the "after" set of EventDestination URIs
            r = sut.session.get(sut.rhost + sut.subscriptions_uri)
            if r.status_code == requests.codes.OK:
                data = r.json()
                new_subs = set([m.get('@odata.id') for m in
                                data.get('Members', []) if '@odata.id' in m])
                diff = new_subs.difference(subs)
                if len(diff) == 1:
                    event_dest_uri = diff.pop()
                elif len(diff) == 0:
                    logging.debug('No EventDestination resource created when '
                                  'SSE stream opened')
                else:
                    logging.debug('More than one (%s) EventDestination '
                                  'resources created when SSE stream opened'
                                  % len(diff))
    except Exception as e:
        logging.warning('Caught %s while opening SSE stream and getting '
                        'EventDestination URI' % e.__class__.__name__)
    return response, event_dest_uri


def _summary_format(sut, result):
    count = sut.summary_count(result)
    start, end = ('', '')
    if count:
        start, end = _color_map[result]
    return start, count, end


def print_summary(sut):
    colorama.init()
    pass_start, passed, pass_end = _summary_format(sut, Result.PASS)
    warn_start, warned, warn_end = _summary_format(sut, Result.WARN)
    fail_start, failed, fail_end = _summary_format(sut, Result.FAIL)
    no_test_start, not_tested, no_test_end = (
        _summary_format(sut, Result.NOT_TESTED))
    print('Summary - %sPASS: %s%s, %sWARN: %s%s, %sFAIL: %s%s, '
          '%sNOT_TESTED: %s%s' % (
           pass_start, passed, pass_end,
           warn_start, warned, warn_end,
           fail_start, failed, fail_end,
           no_test_start, not_tested, no_test_end))
    colorama.deinit()


class SSEClientTimeout(sseclient.SSEClient):
    """Extend SSEClient to provide an optional timeout parameter so we don't
    read the SSE stream forever.
    """
    def __init__(self, event_source, char_enc='utf-8', timeout=None):
        super(SSEClientTimeout, self).__init__(event_source, char_enc=char_enc)
        self._timeout_secs = timeout
        self._timeout_at = None

    def _read(self):
        if self._timeout_secs and self._timeout_at is None:
            self._timeout_at = time.time() + self._timeout_secs
        for data in super(SSEClientTimeout, self)._read():
            if self._timeout_secs and time.time() >= self._timeout_at:
                # stop generator if timeout reached
                return
            yield data


def redfish_version_to_tuple(version: str):
    Version = namedtuple('Version', ['major', 'minor', 'errata'])
    Version.__new__.__defaults__ = (0, 0)
    return Version(*tuple(map(int, version.split('.'))))


def normalize_media_type(media_type):
    """See section 3.1.1.1 of RFC 7231
       e.g. text/HTML; Charset="UTF-8" -> text/html;charset=utf-8"""
    if ';' in media_type:
        mtype, param = media_type.split(';', 2)
        mtype = mtype.strip()
        param = param.replace("'", "").replace('"', '').strip()
        media_type = mtype + ';' + param
    return media_type.lower()


class FakeSocket(io.BytesIO):
    """Helper class to force raw data into an HTTP Response structure"""
    def makefile(self, *args, **kwargs):
        return self


def sanitize(number, minimum, maximum=None):
    """ Sanity check a given number.

    :param number: the number to sanitize
    :param minimum: the minimum acceptable number
    :param maximum: the maximum acceptable number (optional)

    if maximum is not given sanitize return the given value superior
    at minimum

    :returns: an integer who respect the given allowed minimum and maximum
    """
    if number < minimum:
        number = minimum
    elif maximum is not None and number > maximum:
        number = maximum
    return number


def uuid_from_usn(usn, pattern):
    m = pattern.search(usn.lower())
    if m:
        return m.group(1)


def process_ssdp_response(response, discovered_services, pattern):
    response.begin()
    uuid = uuid_from_usn(response.getheader('USN'), pattern)
    if uuid:
        discovered_services[uuid] = response.headers


redfish_usn_pattern = re.compile(
        r'^uuid:([a-f0-9\-]+)::urn:dmtf-org:service:redfish-rest:1(:\d+)?$')

redfish_st_pattern = re.compile(
        r'^urn:dmtf-org:service:redfish-rest:1(:\d+)?$')

uuid_pattern = re.compile(r'^uuid:([a-f0-9\-]+).*$')


def discover_ssdp(port=1900, ttl=2, response_time=3, iface=None,
                  protocol='ipv4', pattern=uuid_pattern,
                  search_target=SSDP_REDFISH):
    """Discovers Redfish services via SSDP

    :param port: the port to use for the SSDP request
    :type port: int
    :param ttl: the time-to-live value for the request
    :type ttl: int
    :param response_time: the number of seconds in which a service can respond
    :type response_time: int
    :param iface: the interface to use for the request; None for all
    :type iface: string
    :param protocol: the protocol to use for the request; 'ipv4' or 'ipv6'
    :type protocol: string
    :param pattern: compiled re pattern for the expected USN header
    :type pattern: SRE_Pattern
    :param search_target: the search target to discover (default: Redfish ST)
    :type search_target: string

    :returns: a set of discovery data
    """
    valid_protocols = ('ipv4', 'ipv6')
    if protocol == 'ipv6':
        mcast_ip = 'ff02::c'
        mcast_connection = (mcast_ip, port, 0, 0)
        af_type = socket.AF_INET6
    elif protocol == 'ipv4':
        mcast_ip = '239.255.255.250'
        mcast_connection = (mcast_ip, port)
        af_type = socket.AF_INET
    else:
        raise ValueError("Invalid protocol type. Expected one of: {}"
                         .format(valid_protocols))

    ttl = sanitize(ttl, minimum=1, maximum=255)
    response_time = sanitize(response_time, minimum=1)

    # Initialize the multicast data
    msearch_str = (
        'M-SEARCH * HTTP/1.1\r\n'
        'Host: {}:{}\r\n'
        'Man: "ssdp:discover"\r\n'
        "ST: {}\r\n"
        "MX: {}\r\n\r\n"
    ).format(mcast_ip, port, search_target, response_time)
    socket.setdefaulttimeout(response_time + 2)

    # Set up the socket and send the request
    sock = socket.socket(af_type, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    if iface:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        str(iface+'\0').encode('utf-8'))
    sock.sendto(bytearray(msearch_str, 'utf-8'), mcast_connection)

    # On the same socket, wait for responses
    discovered_services = {}
    while True:
        try:
            process_ssdp_response(
                http.client.HTTPResponse(FakeSocket(sock.recv(1024))),
                discovered_services, pattern
            )
        except socket.timeout:
            # We hit the timeout; done waiting for responses
            break

    sock.close()
    return discovered_services


def hex_to_binary_str(hex_str: str):
    """Convert hex string to binary string

    @param hex_str: the hex string to convert
    @return: the binary string or None if the input is not a hex string
    """
    try:
        return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
    except ValueError:
        pass


def monobit_frequency(bit_str: str):
    """Frequency (Monobit) Test

    Determine whether the number of ones and zeros in a sequence are
    approximately the same as would be expected for a truly random sequence.

    See section 2.1 in this NIST publication:
    https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=906762
    """
    obs_sum = 0
    n = len(bit_str)
    for i in range(n):
        obs_sum += 1 if bit_str[i] == '1' else -1
    obs_stat = abs(obs_sum) / math.sqrt(n)
    p = math.erfc(obs_stat / math.sqrt(2))
    return p


def runs(bit_str: str):
    """Runs Test

    Determine whether the number of runs of ones and zeros of various
    lengths is as expected for a random sequence.

    See section 2.3 in this NIST publication:
    https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=906762
    """
    n = len(bit_str)

    # pre-test
    ones = 0.0
    for i in range(n):
        ones += int(bit_str[i])
    pi = ones / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau or ones == n:
        # pre-test failed; do not run this test
        return 0.0

    # Runs test
    v_n = 1
    for i in range(n-1):
        v_n += 0 if bit_str[i] == bit_str[i+1] else 1
    p = math.erfc(abs(v_n - 2 * n * pi * (1 - pi)) / (
                2 * math.sqrt(2 * n) * pi * (1 - pi)))
    return p


def random_sequence(token: str):
    """Run randomness tests on the given security token

    @param token: the security token to test as a hex string
    @return: None if token is not hex, True if token is random, False otherwise
    """
    bit_str = hex_to_binary_str(token)
    if bit_str is None:
        return None

    for func in [monobit_frequency, runs]:
        p = func(bit_str)
        logging.debug('P-value of %s test for token %s is %s' %
                      (func.__name__, token, p))
        if p < 0.01:
            # print('P-value of %s test for token %s is %s' %
            #       (func.__name__, token, p))
            return False
    return True
