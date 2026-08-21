# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
import threading
import time
from email.utils import parsedate_to_datetime

import requests

from redfish_protocol_validator import accounts
from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

# A syntactically valid ETag that no service will ever have issued
NEVER_ISSUED_ETAG = '"rpv-never-issued-etag"'
# Delay between the two reads of the ETag stability test
STABILITY_DELAY_SEC = 2
# Number of concurrent writers in the conditional-write race
RACE_WRITERS = 4
# Status codes that indicate the service throttled or serialized the
# concurrent writers rather than evaluating their preconditions
RACE_THROTTLE_CODES = (
    requests.codes.UNAUTHORIZED,
    requests.codes.TOO_MANY_REQUESTS,
    requests.codes.SERVICE_UNAVAILABLE,
)

# RoleId is readable, so every write is observable and a
# representation-derived ETag changes with it; Password renders as
# null. Administrator is never used, so a leaked account cannot hold it.
WRITE_ROLES = ('Operator', 'ReadOnly')

ETAG_ASSERTIONS = [
    Assertion.PROTO_ETAG_HEADER_AND_PROPERTY,
    Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION,
    Assertion.PROTO_ETAG_CONDITIONAL_GET,
    Assertion.PROTO_ETAG_IF_MATCH_ENFORCED,
    Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED,
    Assertion.PROTO_ETAG_LOST_UPDATE,
    Assertion.PROTO_ETAG_ROTATES_ON_WRITE,
]


def _succeeded(response):
    """Report whether a response carries a success status.

    Response.ok cannot be used here: the system-under-test synthesizes
    status 600 for a request that raised a transport exception, and
    raise_for_status only raises for 4xx and 5xx, so ok is True for it.
    """
    return 200 <= response.status_code < 300


def _evaluated(status):
    """Report whether the service evaluated the request.

    A 401 was refused before the precondition was considered; a
    synthesized transport failure (600+) lost its outcome, and the
    write can still have been applied.
    """
    return status < 600 and status != requests.codes.UNAUTHORIZED


def _get_etags(sut: SystemUnderTest, uri):
    """GET uri and return (response, header ETag, @odata.etag property)."""
    response = sut.get(uri)
    header_etag, body_etag = None, None
    if _succeeded(response):
        header_etag = response.headers.get('ETag')
        if utils.get_response_media_type(response) == 'application/json':
            body_etag = utils.get_response_json(response).get('@odata.etag')
    return response, header_etag, body_etag


def _role_of(response):
    """Return the RoleId from an account response, or None."""
    if utils.get_response_media_type(response) == 'application/json':
        return utils.get_response_json(response).get('RoleId')
    return None


def _other_role(role):
    """Return the write role that differs from the given role;
    anything outside the pair flips to ReadOnly, never upward."""
    if role == WRITE_ROLES[1]:
        return WRITE_ROLES[0]
    return WRITE_ROLES[1]


def _patch_role(sut: SystemUnderTest, acct_uri, role, etag):
    """PATCH the account RoleId with the given If-Match value.

    The ETag is sent verbatim, weak prefix included; services should
    perform weak comparison when verifying client-supplied ETags.
    """
    return sut.patch(acct_uri, json={'RoleId': role},
                     headers={'If-Match': etag})


def _verify_role(sut: SystemUnderTest, acct_uri, expected_role):
    """GET the account and compare its RoleId to the expected role.

    Returns (verdict, detail); verdict is None when the read did not
    answer, so a broken channel is never read as a definite outcome.
    """
    response = sut.get(acct_uri)
    if not _succeeded(response):
        return None, 'the verification GET returned status %s' % (
            response.status_code)
    role = _role_of(response)
    if role is None:
        return None, 'the verification GET returned no RoleId property'
    return role == expected_role, "the account's RoleId is '%s'" % role


def _race_conditional_writes(sut: SystemUnderTest, acct_uri, etag, role):
    """Fire simultaneous PATCH requests that carry the same If-Match.

    Connections are pre-warmed so the racing requests do not serialize
    behind TCP/TLS setup. Every writer requests the same role: RoleId
    has too few values for per-writer attribution, so the race checks
    for one acceptance. Returns one response (or None) per writer.
    """
    barrier = threading.Barrier(RACE_WRITERS, timeout=60)
    responses = [None] * RACE_WRITERS

    def writer(index):
        session = requests.Session()
        session.auth = (sut.username, sut.password)
        session.verify = sut.verify
        try:
            session.get(sut.rhost + acct_uri, timeout=30)
            barrier.wait()
            responses[index] = session.patch(
                sut.rhost + acct_uri,
                json={'RoleId': role},
                headers={'If-Match': etag}, timeout=30)
        except Exception as e:
            logging.warning('Concurrent conditional PATCH %s raised %s: %s'
                            % (index, e.__class__.__name__, e))
        finally:
            session.close()

    threads = [threading.Thread(target=writer, args=(i,))
               for i in range(RACE_WRITERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return responses


def _classify_race(statuses):
    """Split race statuses into (winners, losers_412, losers_other,
    incomplete) index lists; None means the request never completed,
    which is never a verdict about the service.
    """
    winners, losers_412, losers_other, incomplete = [], [], [], []
    for index, status in enumerate(statuses):
        if status is None:
            incomplete.append(index)
        elif 200 <= status < 300:
            winners.append(index)
        elif status == requests.codes.PRECONDITION_FAILED:
            losers_412.append(index)
        else:
            losers_other.append(index)
    return winners, losers_412, losers_other, incomplete


# Write-pairs attempted by the tag-resolution probe; each pair needs the
# service to cooperate, so one coarse tag is usually caught on the first
PROBE_PAIRS = 3
# How far a numeric tag may sit from the response's own clock and still
# be read as a wall-clock value, covering clock skew and the age of the
# last write
CLOCK_TAG_TOLERANCE_SEC = 300


def _tag_tracks_the_clock(response, etag):
    """Report whether the ETag looks like a wall-clock timestamp,
    by comparing a numeric tag against the response's own Date header.

    A clock tag cannot distinguish writes inside one tick; a non-clock
    tag changes per write, so shared-tag winners got in because the
    service let them. Returns None when either value cannot be read or
    a numeric tag sits too far from the clock to classify.
    """
    date_header = response.headers.get('Date')
    if not date_header or etag is None:
        return None
    try:
        value = int(etag.strip().lstrip('Ww/').strip('"'))
    except ValueError:
        # A non-numeric tag is a hash or an opaque string, neither of
        # which is a clock
        return False
    try:
        served_at = parsedate_to_datetime(date_header).timestamp()
    except (TypeError, ValueError):
        return None
    if abs(value - served_at) <= CLOCK_TAG_TOLERANCE_SEC:
        return True
    # Numeric but far from the clock is unknown: it could be a counter,
    # or a last-modified timestamp on a resource idle longer than the
    # tolerance
    return None


def _probe_write_and_read(sut: SystemUnderTest, acct_uri, role, etag):
    """Apply a conditional write, returning (resulting tag, start time)."""
    started = time.monotonic()
    response = _patch_role(sut, acct_uri, role, etag)
    if _succeeded(response):
        response, new_etag, _ = _get_etags(sut, acct_uri)
        if _succeeded(response):
            return new_etag, started
    return None, started


def _probe_write_pair(sut: SystemUnderTest, acct_uri, current_role, etag):
    """Run one write pair, flipping the role away and back so both
    writes change the representation and the account ends as it began.

    Returns (outcome, gap_ms, tag to continue from).
    """
    first, first_at = _probe_write_and_read(sut, acct_uri,
                                            _other_role(current_role), etag)
    if first is None:
        return 'inconclusive', None, None
    second, second_at = _probe_write_and_read(sut, acct_uri, current_role,
                                              first)
    gap_ms = int((second_at - first_at) * 1000)
    if second is None:
        return 'inconclusive', gap_ms, None
    return ('coarse' if first == second else 'rotates'), gap_ms, second


def _probe_tag_resolution(sut: SystemUnderTest, acct_uri):
    """Determine whether the tag distinguishes two consecutive writes.

    The same tag from two applied writes proves it cannot ('coarse').
    Distinct tags only show the writes were far enough apart for this
    tag ('rotates'), since the probe cannot write faster than the
    service answers; gap_ms records the closest spacing achieved.

    Returns ('coarse'|'rotates'|'inconclusive', gap_ms).
    """
    response, etag, _ = _get_etags(sut, acct_uri)
    if not _succeeded(response) or etag is None:
        return 'inconclusive', None
    current_role = _role_of(response)
    best_gap = None
    for _ in range(PROBE_PAIRS):
        outcome, gap_ms, etag = _probe_write_pair(sut, acct_uri,
                                                  current_role, etag)
        if gap_ms is not None and (best_gap is None or gap_ms < best_gap):
            best_gap = gap_ms
        if outcome != 'rotates':
            return outcome, best_gap
    return 'rotates', best_gap


def _multi_winner_message(statuses, winners, race_etag, probe):
    """Return the message naming which failure a multi-winner race is,
    given the tag-resolution probe's outcome."""
    prefix = ('%s of %s simultaneous PATCH requests carrying the same '
              'If-Match value %s were accepted (statuses %s); ' %
              (len(winners), RACE_WRITERS, race_etag, statuses))
    outcome, gap_ms = probe
    if outcome == 'not-a-clock':
        return (prefix + 'the ETag does not track the service clock, so it '
                'changes with the write rather than with the time, and it '
                'would have distinguished these writers had the service '
                'applied one write before checking the next precondition. '
                'The precondition check and the write are not atomic; '
                'writers with differing payloads would lose updates')
    if outcome == 'coarse':
        return (prefix + 'a follow-up probe found two writes %s ms apart '
                'that produced the same ETag, so the tag cannot '
                'distinguish writes this close together, no matter how the '
                'service serializes them. An ETag built from a coarse '
                'value, such as a second-granularity timestamp, behaves '
                'this way' % gap_ms)
    if outcome == 'clock':
        return (prefix + 'the ETag tracks the service clock, so its '
                'resolution bounds what a precondition can arbitrate and '
                'writers inside one tick share a tag whatever the service '
                'does. The tag is the defect this test can name; whether '
                'the precondition check is also non-atomic is not '
                'determined')
    if outcome == 'rotates':
        return (prefix + 'a follow-up probe saw consecutive writes produce '
                'different ETags, but the closest it could space two '
                'writes was %s ms, so it did not test whether the tag '
                'distinguishes writes closer than that. Either the '
                'precondition check is not atomic, or the tag is too '
                'coarse for the interval the racing writers achieved'
                % gap_ms)
    return (prefix + 'either the precondition check and the write are not '
            'atomic, or the tag is too coarse to distinguish writes this '
            'close together; a follow-up probe could not determine which')


def _diagnose_multi_winner(sut: SystemUnderTest, acct_uri, race_etag):
    """Name the cause of a race that admitted more than one winner:
    a non-clock tag would have separated the writers, so the failure is
    atomicity; a clock tag falls to the slower write-pair probe.

    Returns the (outcome, gap_ms) pair _race_verdict() reports on.
    """
    response = sut.get(acct_uri)
    is_clock = _tag_tracks_the_clock(response, race_etag)
    if is_clock is False:
        return 'not-a-clock', None
    outcome, gap_ms = _probe_tag_resolution(sut, acct_uri)
    if outcome == 'rotates' and is_clock:
        outcome = 'clock'
    return outcome, gap_ms


def _race_verdict(statuses, classification, race_etag, probe):
    """Return (Result, message) for a race outcome, or None when the race
    produced one clean winner whose write the caller still has to verify.

    probe is the _probe_tag_resolution() outcome, needed only to name
    which failure a multi-winner race is; pass None otherwise.
    """
    winners, losers_412, losers_other, incomplete = classification
    throttled = [i for i in losers_other
                 if statuses[i] in RACE_THROTTLE_CODES]

    if len(winners) > 1:
        return (Result.FAIL,
                _multi_winner_message(statuses, winners, race_etag, probe))
    if incomplete:
        # A verdict about the connection, not the service
        return (Result.NOT_TESTED,
                '%s of %s simultaneous PATCH requests did not complete '
                '(connection failure or timeout; statuses %s); unable to '
                'fully exercise conditional-write atomicity'
                % (len(incomplete), RACE_WRITERS, statuses))
    if losers_other and len(throttled) == len(losers_other):
        return (Result.NOT_TESTED,
                'The service throttled or refused concurrent requests '
                '(statuses %s); atomicity could not be fully exercised'
                % (statuses,))
    if losers_other:
        if winners:
            return (Result.FAIL,
                    'Losing simultaneous PATCH requests must be rejected '
                    'with 412 Precondition Failed; got statuses %s'
                    % (statuses,))
        return (Result.NOT_TESTED,
                'Unable to exercise simultaneous conditional writes; '
                'requests returned unexpected statuses %s' % (statuses,))
    if not winners:
        return (Result.FAIL,
                'No simultaneous PATCH request succeeded; every writer was '
                'rejected with 412 against the ETag it had just read '
                '(statuses %s)' % (statuses,))
    return None


def test_header_and_property(sut: SystemUnderTest, acct_uri, header_etag,
                             body_etag):
    """Perform tests for Assertion.PROTO_ETAG_HEADER_AND_PROPERTY."""
    # Exact comparison is safe: the system under test sends
    # Accept-Encoding: identity, so no content coding varies the header
    # tag from the property (RFC 7232)
    if body_etag is None:
        msg = ('Resource returned the ETag header %s but no @odata.etag '
               'property' % header_etag)
        sut.log(Result.WARN, 'GET', requests.codes.OK, acct_uri,
                Assertion.PROTO_ETAG_HEADER_AND_PROPERTY, msg)
    elif body_etag != header_etag:
        msg = ('The @odata.etag property %s does not equal the ETag header '
               '%s; a client that builds If-Match from one of them will '
               'fail the precondition' % (body_etag, header_etag))
        sut.log(Result.WARN, 'GET', requests.codes.OK, acct_uri,
                Assertion.PROTO_ETAG_HEADER_AND_PROPERTY, msg)
    else:
        sut.log(Result.PASS, 'GET', requests.codes.OK, acct_uri,
                Assertion.PROTO_ETAG_HEADER_AND_PROPERTY, 'Test passed')


def test_etag_stability(sut: SystemUnderTest, acct_uri, header_etag):
    """Perform tests for Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION."""
    time.sleep(STABILITY_DELAY_SEC)
    response, reread_etag, _ = _get_etags(sut, acct_uri)
    if not _succeeded(response) or reread_etag is None:
        msg = ('GET request to %s failed or returned no ETag on the second '
               'read; unable to test this assertion' % acct_uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION, msg)
        return
    if reread_etag != header_etag:
        msg = ('ETag changed from %s to %s across reads %s seconds apart '
               'with no intervening write; an ETag that changes without a '
               'modification, such as one calculated over a DateTime '
               'property, cannot satisfy an If-Match precondition built '
               'from a recent read' %
               (header_etag, reread_etag, STABILITY_DELAY_SEC))
        sut.log(Result.WARN, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION, msg)
    else:
        sut.log(Result.PASS, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION,
                'Test passed')


def test_conditional_get(sut: SystemUnderTest, acct_uri, header_etag):
    """Perform tests for Assertion.PROTO_ETAG_CONDITIONAL_GET."""
    response = sut.get(acct_uri, headers={'If-None-Match': header_etag})
    if response.status_code == requests.codes.NOT_MODIFIED:
        sut.log(Result.PASS, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_CONDITIONAL_GET, 'Test passed')
    elif not _evaluated(response.status_code):
        msg = ('Conditional GET returned status %s; the credential was '
               'refused before the precondition was considered, or the '
               'outcome was lost in transport' % response.status_code)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_CONDITIONAL_GET, msg)
    elif _succeeded(response):
        msg = ('GET with a matching If-None-Match header returned %s with a '
               'full body; expected 304 Not Modified. Support for '
               'If-None-Match is optional, but without it clients cannot '
               'revalidate a resource without transferring it' %
               response.status_code)
        sut.log(Result.WARN, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_CONDITIONAL_GET, msg)
    else:
        msg = ('GET with a matching If-None-Match header failed with status '
               '%s; extended error: %s' %
               (response.status_code, utils.get_extended_error(response)))
        sut.log(Result.WARN, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_CONDITIONAL_GET, msg)


def test_never_issued_etag_rejected(sut: SystemUnderTest, acct_uri,
                                    current_role):
    """Perform the never-issued If-Match tests for
    Assertion.PROTO_ETAG_IF_MATCH_ENFORCED and
    Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED."""
    response = _patch_role(sut, acct_uri, _other_role(current_role),
                           NEVER_ISSUED_ETAG)
    if not _evaluated(response.status_code):
        msg = ('PATCH with a never-issued If-Match value returned status '
               '%s; the credential was refused before the precondition was '
               'considered, or the outcome was lost in transport' %
               response.status_code)
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED, msg)
        return
    if response.status_code != requests.codes.PRECONDITION_FAILED:
        if _succeeded(response):
            msg = ('PATCH with If-Match value %s, which the service never '
                   'issued, succeeded with status %s; expected 412 '
                   'Precondition Failed' %
                   (NEVER_ISSUED_ETAG, response.status_code))
        else:
            # Still a failure: RFC 9110 evaluates preconditions before
            # request content, so a content error cannot displace the 412
            msg = ('PATCH with If-Match value %s, which the service never '
                   'issued, returned status %s rather than a write '
                   'acceptance; expected 412 Precondition Failed; '
                   'extended error: %s' %
                   (NEVER_ISSUED_ETAG, response.status_code,
                    utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        return
    sut.log(Result.PASS, 'PATCH', response.status_code, acct_uri,
            Assertion.PROTO_ETAG_IF_MATCH_ENFORCED,
            'Test passed for never-issued If-Match value')
    verdict, detail = _verify_role(sut, acct_uri, current_role)
    if verdict:
        sut.log(Result.PASS, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED, 'Test passed')
    elif verdict is None:
        msg = ('PATCH was rejected with 412, but %s; unable to determine '
               'whether the rejected write was applied' % detail)
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED, msg)
    else:
        msg = ('PATCH was rejected with 412, but %s rather than the prior '
               "'%s'; the rejected write was applied" %
               (detail, current_role))
        sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED, msg)


def test_current_etag_accepted(sut: SystemUnderTest, acct_uri):
    """Perform the matching If-Match tests for
    Assertion.PROTO_ETAG_IF_MATCH_ENFORCED.

    Returns (pre-write ETag, the role written) on success, (etag, None)
    otherwise.
    """
    response, pre_write_etag, _ = _get_etags(sut, acct_uri)
    if not _succeeded(response) or pre_write_etag is None:
        msg = ('GET request to %s failed or returned no ETag header to use '
               'for If-Match; unable to test this assertion' % acct_uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        return None, None
    new_role = _other_role(_role_of(response))
    response = _patch_role(sut, acct_uri, new_role, pre_write_etag)
    if not _evaluated(response.status_code):
        msg = ('PATCH with the current ETag %s in If-Match returned status '
               '%s; the credential was refused before the precondition was '
               'considered, or the outcome was lost in transport' %
               (pre_write_etag, response.status_code))
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        return pre_write_etag, None
    if not _succeeded(response):
        msg = ('PATCH with the current ETag %s in If-Match returned status '
               '%s; expected success; extended error: %s' %
               (pre_write_etag, response.status_code,
                utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        return pre_write_etag, None
    verdict, detail = _verify_role(sut, acct_uri, new_role)
    if not verdict:
        if verdict is None:
            msg = ('PATCH with the current ETag %s in If-Match returned '
                   'status %s, but %s; unable to verify the write' %
                   (pre_write_etag, response.status_code, detail))
            sut.log(Result.NOT_TESTED, 'PATCH', response.status_code,
                    acct_uri, Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        elif response.status_code == requests.codes.ACCEPTED:
            msg = ('PATCH with the current ETag %s in If-Match was accepted '
                   'asynchronously (202) and the write is not yet '
                   'observable' % pre_write_etag)
            sut.log(Result.WARN, 'PATCH', response.status_code, acct_uri,
                    Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        else:
            msg = ('PATCH with the current ETag %s in If-Match returned '
                   "status %s, but %s rather than the requested '%s'" %
                   (pre_write_etag, response.status_code, detail, new_role))
            sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                    Assertion.PROTO_ETAG_IF_MATCH_ENFORCED, msg)
        return pre_write_etag, None
    sut.log(Result.PASS, 'PATCH', response.status_code, acct_uri,
            Assertion.PROTO_ETAG_IF_MATCH_ENFORCED,
            'Test passed for matching If-Match value')
    return pre_write_etag, new_role


def test_lost_update_prevented(sut: SystemUnderTest, acct_uri,
                               pre_write_etag, current_role):
    """Perform tests for Assertion.PROTO_ETAG_LOST_UPDATE."""
    response = _patch_role(sut, acct_uri, _other_role(current_role),
                           pre_write_etag)
    if not _evaluated(response.status_code):
        msg = ('PATCH replaying the stale If-Match value %s returned status '
               '%s; the credential was refused before the precondition was '
               'considered, or the outcome was lost in transport' %
               (pre_write_etag, response.status_code))
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_LOST_UPDATE, msg)
        return
    if response.status_code != requests.codes.PRECONDITION_FAILED:
        if _succeeded(response):
            msg = ('PATCH with If-Match value %s, which was read before an '
                   'intervening write and is now stale, succeeded with '
                   'status %s; expected 412 Precondition Failed. Two '
                   'writers that hold the same ETag can silently overwrite '
                   'each other\'s update' %
                   (pre_write_etag, response.status_code))
        else:
            msg = ('PATCH with the stale If-Match value %s returned status '
                   '%s; expected 412 Precondition Failed; extended error: '
                   '%s' % (pre_write_etag, response.status_code,
                           utils.get_extended_error(response)))
        sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_LOST_UPDATE, msg)
        return
    verdict, detail = _verify_role(sut, acct_uri, current_role)
    if verdict:
        sut.log(Result.PASS, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_LOST_UPDATE, 'Test passed')
    elif verdict is None:
        msg = ('The stale If-Match value was rejected with 412, but %s; '
               'unable to determine whether the rejected write was applied'
               % detail)
        sut.log(Result.NOT_TESTED, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_LOST_UPDATE, msg)
    else:
        msg = ('The stale If-Match value was rejected with 412, but %s '
               "rather than the intervening write's '%s'; the rejected "
               'write was applied' % (detail, current_role))
        sut.log(Result.FAIL, 'PATCH', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_LOST_UPDATE, msg)


def test_etag_rotates_on_write(sut: SystemUnderTest, acct_uri,
                               pre_write_etag):
    """Perform tests for Assertion.PROTO_ETAG_ROTATES_ON_WRITE.

    Returns the post-write ETag, or None if it could not be read.
    """
    response, post_write_etag, _ = _get_etags(sut, acct_uri)
    if not _succeeded(response) or post_write_etag is None:
        msg = ('GET request to %s failed or returned no ETag after a '
               'successful PATCH; unable to test this assertion' % acct_uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_ROTATES_ON_WRITE, msg)
        return None
    if post_write_etag == pre_write_etag:
        msg = ('ETag %s did not change after a successful PATCH that '
               'changed the RoleId property; an ETag that survives an '
               'observable modification cannot invalidate stale copies '
               'held by other clients' % pre_write_etag)
        sut.log(Result.WARN, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_ROTATES_ON_WRITE, msg)
    else:
        sut.log(Result.PASS, 'GET', response.status_code, acct_uri,
                Assertion.PROTO_ETAG_ROTATES_ON_WRITE, 'Test passed')
    return post_write_etag


def test_concurrent_conditional_writes(sut: SystemUnderTest, acct_uri):
    """Perform the conditional-write race test for
    Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS.

    Same If-Match on every writer; exactly one must win and the rest
    draw 412. One round only, so a PASS bounds rather than proves
    atomicity.
    """
    assertion = Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS
    response, race_etag, _ = _get_etags(sut, acct_uri)
    if not _succeeded(response) or race_etag is None:
        msg = ('GET request to %s failed or returned no ETag header to use '
               'for If-Match; unable to test this assertion' % acct_uri)
        sut.log(Result.NOT_TESTED, 'GET', response.status_code, acct_uri,
                assertion, msg)
        return
    target_role = _other_role(_role_of(response))
    responses = _race_conditional_writes(sut, acct_uri, race_etag,
                                         target_role)
    statuses = [r.status_code if r is not None else None for r in responses]
    classification = _classify_race(statuses)
    winners, losers_412, _, _ = classification

    if len(winners) > 1:
        # A failure whether or not the other writers completed; a 202
        # counts as accepted
        probe = _diagnose_multi_winner(sut, acct_uri, race_etag)
    else:
        probe = None
    verdict = _race_verdict(statuses, classification, race_etag, probe)
    if verdict is not None:
        result, msg = verdict
        status = statuses[winners[0]] if winners else ''
        sut.log(result, 'PATCH', status, acct_uri, assertion, msg)
        return
    role_verdict, detail = _verify_role(sut, acct_uri, target_role)
    if role_verdict:
        msg = ('Test passed: %s simultaneous conditional writes, one '
               'winner, %s rejected with 412' %
               (RACE_WRITERS, len(losers_412)))
        sut.log(Result.PASS, 'PATCH', statuses[winners[0]], acct_uri,
                assertion, msg)
    elif (role_verdict is False and
            statuses[winners[0]] == requests.codes.ACCEPTED):
        msg = ('The winning PATCH was accepted asynchronously (202) and '
               'the write is not yet observable')
        sut.log(Result.WARN, 'PATCH', statuses[winners[0]], acct_uri,
                assertion, msg)
    elif role_verdict is None:
        msg = ('Exactly one simultaneous PATCH succeeded, but %s; unable '
               'to verify the winning write' % detail)
        sut.log(Result.NOT_TESTED, 'PATCH', statuses[winners[0]], acct_uri,
                assertion, msg)
    else:
        msg = ('Exactly one simultaneous PATCH succeeded, but %s rather '
               "than the requested '%s'" % (detail, target_role))
        sut.log(Result.FAIL, 'PATCH', statuses[winners[0]], acct_uri,
                assertion, msg)


def test_etags(sut: SystemUnderTest):
    """Perform live ETag write-semantics tests against a temporary
    ManagerAccount, the one resource where ETag support is required
    (sections 6.5, 7.1, and 13.5.1). Writes flip RoleId between two
    standard roles and are verified by reading the property back.
    """
    user, password, acct_uri = accounts.add_account(sut, sut.session)
    if not acct_uri:
        msg = ('Failed to create an account to test ETag write semantics; '
               'unable to test these assertions')
        for assertion in ETAG_ASSERTIONS:
            sut.log(Result.NOT_TESTED, '', '', '', assertion, msg)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)
        return
    try:
        response, header_etag, body_etag = _get_etags(sut, acct_uri)
        if not _succeeded(response) or header_etag is None:
            # ETag presence on ManagerAccount GETs is scored by
            # PROTO_ETAG_ON_GET_ACCOUNT; without a tag there is no
            # write-semantics contract to test
            msg = ('GET request to %s did not return an ETag header; '
                   'unable to test this assertion' % acct_uri)
            for assertion in ETAG_ASSERTIONS:
                sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                        acct_uri, assertion, msg)
            sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                    acct_uri, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)
            return
        initial_role = _role_of(response)
        if initial_role is None:
            # Without the property the write tests can neither pick a
            # role nor verify one
            msg = ('GET request to %s did not return a RoleId property; '
                   'unable to verify writes for this assertion' % acct_uri)
            for assertion in [Assertion.PROTO_ETAG_IF_MATCH_ENFORCED,
                              Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED,
                              Assertion.PROTO_ETAG_LOST_UPDATE,
                              Assertion.PROTO_ETAG_ROTATES_ON_WRITE]:
                sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                        acct_uri, assertion, msg)
            sut.log(Result.NOT_TESTED, 'GET', response.status_code,
                    acct_uri, Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS, msg)
            test_header_and_property(sut, acct_uri, header_etag, body_etag)
            test_etag_stability(sut, acct_uri, header_etag)
            test_conditional_get(sut, acct_uri, header_etag)
            return
        test_header_and_property(sut, acct_uri, header_etag, body_etag)
        test_etag_stability(sut, acct_uri, header_etag)
        test_conditional_get(sut, acct_uri, header_etag)
        test_never_issued_etag_rejected(sut, acct_uri, initial_role)
        pre_write_etag, new_role = test_current_etag_accepted(sut, acct_uri)
        if new_role:
            test_lost_update_prevented(sut, acct_uri, pre_write_etag,
                                       new_role)
            test_etag_rotates_on_write(sut, acct_uri, pre_write_etag)
        else:
            msg = ('PATCH with the current ETag in If-Match did not '
                   'observably succeed; unable to test this assertion')
            sut.log(Result.NOT_TESTED, '', '', acct_uri,
                    Assertion.PROTO_ETAG_LOST_UPDATE, msg)
            sut.log(Result.NOT_TESTED, '', '', acct_uri,
                    Assertion.PROTO_ETAG_ROTATES_ON_WRITE, msg)
        test_concurrent_conditional_writes(sut, acct_uri)
    finally:
        accounts.delete_account(sut, sut.session, user, acct_uri)
