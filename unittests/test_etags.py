# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import unittest
from unittest import mock, TestCase

import requests

from redfish_protocol_validator import etags
from redfish_protocol_validator.constants import Assertion, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

ACCT_URI = '/redfish/v1/AccountService/Accounts/9'
USER = 'rfpvtest'
PASSWORD = 'OrigPass1_'

# A Date header and a numeric ETag equal to it, as epoch seconds
DATE_HEADER = 'Thu, 06 Aug 2026 22:00:00 GMT'
DATE_EPOCH_ETAG = '"1786053600"'

# The GETs test_etags() performs in order, for building mock sequences
# by name rather than by index
GET_SLOTS = (
    'initial',
    'stability',
    'conditional_get',
    'verify_after_412',
    'pre_write',
    'verify_new_role',
    'verify_after_replay',
    'rotation',
    'race_read',
    'verify_race_winner',
)


def _response(status_code=200, etag=None, body_etag=None, role=None,
              date=None):
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status_code
    # Mirror requests: raise_for_status raises only for 4xx and 5xx, so
    # ok is True for the 600 the SUT synthesizes from a transport
    # exception
    resp.ok = not (400 <= status_code < 600)
    headers = {'Content-Type': 'application/json'}
    if etag is not None:
        headers['ETag'] = etag
    if date is not None:
        headers['Date'] = date
    resp.headers = headers
    body = {}
    if body_etag is not None:
        body['@odata.etag'] = body_etag
    if role is not None:
        body['RoleId'] = role
    resp.json.return_value = body
    return resp


class EtagsNoSut(TestCase):
    """Tests for the pure helpers."""

    def test_succeeded_rejects_synthesized_transport_status(self):
        # The SUT builds a 600 response from a transport exception, and
        # Response.ok is True for it because raise_for_status only
        # raises for 4xx and 5xx
        self.assertTrue(_response(200).ok)
        self.assertTrue(_response(600).ok)
        self.assertTrue(etags._succeeded(_response(200)))
        self.assertFalse(etags._succeeded(_response(600)))
        self.assertFalse(etags._succeeded(_response(304)))

    def test_tag_tracks_the_clock(self):
        served = _response(date=DATE_HEADER)
        # a tag equal to the service clock is a wall-clock value
        self.assertTrue(
            etags._tag_tracks_the_clock(served, DATE_EPOCH_ETAG))
        # a counter or a hash is not
        self.assertFalse(etags._tag_tracks_the_clock(served, '"42"'))
        self.assertFalse(
            etags._tag_tracks_the_clock(served, '"a1b2c3d4"'))
        self.assertFalse(
            etags._tag_tracks_the_clock(served, 'W/"a1b2c3d4"'))
        # unreadable inputs answer neither way
        self.assertIsNone(etags._tag_tracks_the_clock(_response(), '"1"'))
        self.assertIsNone(etags._tag_tracks_the_clock(served, None))

    def test_evaluated(self):
        self.assertTrue(etags._evaluated(412))
        self.assertTrue(etags._evaluated(500))
        self.assertFalse(etags._evaluated(401))
        self.assertFalse(etags._evaluated(600))

    def test_other_role(self):
        self.assertEqual(etags._other_role('Operator'), 'ReadOnly')
        self.assertEqual(etags._other_role('ReadOnly'), 'Operator')
        # any role outside the write pair flips to ReadOnly, never upward
        self.assertEqual(etags._other_role('Administrator'), 'ReadOnly')
        self.assertEqual(etags._other_role(None), 'ReadOnly')

    def verdict(self, statuses, race_etag='"E1"', probe=None):
        return etags._race_verdict(statuses, etags._classify_race(statuses),
                                   race_etag, probe)

    def test_race_verdict_clean_winner_defers(self):
        self.assertIsNone(self.verdict([412, 200, 412, 412]))

    def test_race_verdict_multi_winner_names_cause(self):
        result, msg = self.verdict([200, 200, 412, 412],
                                   probe=('not-a-clock', None))
        self.assertEqual(result, Result.FAIL)
        self.assertIn('are not atomic', msg)
        result, msg = self.verdict([200, 200, 412, 412],
                                   probe=('clock', None))
        self.assertEqual(result, Result.FAIL)
        self.assertIn('tracks the service clock', msg)
        result, msg = self.verdict([200, 200, 412, 412],
                                   probe=('rotates', 740))
        self.assertEqual(result, Result.FAIL)
        self.assertIn('closest it could space two writes was 740 ms', msg)
        result, msg = self.verdict([200, 200, 412, 412],
                                   probe=('coarse', 310))
        self.assertEqual(result, Result.FAIL)
        self.assertIn('two writes 310 ms apart', msg)
        result, msg = self.verdict([200, 200, 412, 412],
                                   probe=('inconclusive', None))
        self.assertEqual(result, Result.FAIL)
        self.assertIn('could not determine', msg)

    def test_race_verdict_incomplete_and_throttled(self):
        self.assertEqual(self.verdict([200, 412, 412, None])[0],
                         Result.NOT_TESTED)
        self.assertEqual(self.verdict([200, 503, 412, 412])[0],
                         Result.NOT_TESTED)

    def test_race_verdict_failures(self):
        self.assertEqual(self.verdict([412, 412, 412, 412])[0], Result.FAIL)
        self.assertEqual(self.verdict([200, 500, 412, 412])[0], Result.FAIL)

    def test_classify_race_one_winner(self):
        winners, losers_412, losers_other, incomplete = etags._classify_race(
            [412, 200, 412, 412])
        self.assertEqual(winners, [1])
        self.assertEqual(losers_412, [0, 2, 3])
        self.assertEqual(losers_other, [])
        self.assertEqual(incomplete, [])

    def test_classify_race_two_winners(self):
        winners, losers_412, losers_other, incomplete = etags._classify_race(
            [200, 204, 412, 412])
        self.assertEqual(winners, [0, 1])
        self.assertEqual(losers_412, [2, 3])
        self.assertEqual(losers_other, [])
        self.assertEqual(incomplete, [])

    def test_classify_race_throttled_and_incomplete(self):
        winners, losers_412, losers_other, incomplete = etags._classify_race(
            [200, 503, 412, None])
        self.assertEqual(winners, [0])
        self.assertEqual(losers_412, [2])
        self.assertEqual(losers_other, [1])
        self.assertEqual(incomplete, [3])


class Etags(TestCase):

    def setUp(self):
        super(Etags, self).setUp()
        self.sut = SystemUnderTest('https://127.0.0.1:8000', 'oper', 'xyzzy')
        patcher = mock.patch(
            'redfish_protocol_validator.etags.accounts', autospec=True)
        self.mock_accounts = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_accounts.add_account.return_value = (
            USER, PASSWORD, ACCT_URI)

    def result(self, assertion):
        return [entry['result'] for entry in
                self.sut.results.get(assertion, [])]

    def happy_path_gets(self, **overrides):
        """The GET sequence of a fully conformant run; override slots by
        name from GET_SLOTS."""
        responses = {
            'initial': _response(etag='"E1"', body_etag='"E1"',
                                 role='ReadOnly'),
            'stability': _response(etag='"E1"', body_etag='"E1"',
                                   role='ReadOnly'),
            'conditional_get': _response(status_code=304),
            'verify_after_412': _response(role='ReadOnly'),
            'pre_write': _response(etag='"E1"', body_etag='"E1"',
                                   role='ReadOnly'),
            'verify_new_role': _response(role='Operator'),
            'verify_after_replay': _response(role='Operator'),
            'rotation': _response(etag='"E2"', body_etag='"E2"',
                                  role='Operator'),
            'race_read': _response(etag='"E2"', body_etag='"E2"',
                                   role='Operator'),
            'verify_race_winner': _response(role='ReadOnly'),
        }
        unknown = set(overrides) - set(GET_SLOTS)
        assert not unknown, 'unknown GET slots: %s' % unknown
        responses.update(overrides)
        return [responses[slot] for slot in GET_SLOTS]

    def happy_path_patches(self):
        return [
            _response(status_code=412),  # never-issued tag
            _response(),                 # current tag
            _response(status_code=412),  # stale replay
        ]

    def happy_race(self):
        return [
            _response(status_code=412), _response(),
            _response(status_code=412), _response(status_code=412)]

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_etags_pass(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()) as mock_patch:
            etags.test_etags(self.sut)
        # exact counts, so a test that silently never ran cannot pass
        expected = {
            Assertion.PROTO_ETAG_HEADER_AND_PROPERTY: 1,
            Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION: 1,
            Assertion.PROTO_ETAG_CONDITIONAL_GET: 1,
            Assertion.PROTO_ETAG_IF_MATCH_ENFORCED: 2,
            Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED: 1,
            Assertion.PROTO_ETAG_LOST_UPDATE: 1,
            Assertion.PROTO_ETAG_ROTATES_ON_WRITE: 1,
            Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS: 1,
        }
        for assertion, count in expected.items():
            self.assertEqual(self.result(assertion), [Result.PASS] * count,
                             'assertion %s' % assertion.name)
        # every write flips RoleId; nothing touches Password
        for _, kwargs in mock_patch.call_args_list:
            self.assertIn('RoleId', kwargs['json'])
            self.assertNotIn('Password', kwargs['json'])
        self.assertEqual(self.mock_accounts.delete_account.call_count, 1)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_never_issued_etag_accepted_fails(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        patches = self.happy_path_patches()
        patches[0] = _response()  # bogus If-Match accepted
        gets = self.happy_path_gets(
            verify_after_412=_response(role='Operator'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(self.sut, 'patch', side_effect=patches):
            etags.test_etags(self.sut)
        self.assertIn(Result.FAIL,
                      self.result(Assertion.PROTO_ETAG_IF_MATCH_ENFORCED))

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_stale_replay_accepted_fails(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        patches = self.happy_path_patches()
        patches[2] = _response()  # stale If-Match accepted: lost update
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(self.sut, 'patch', side_effect=patches):
            etags.test_etags(self.sut)
        self.assertEqual(self.result(Assertion.PROTO_ETAG_LOST_UPDATE),
                         [Result.FAIL])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_412_but_write_applied_fails(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        # the rejected write's role shows up on the verification read
        gets = self.happy_path_gets(
            verify_after_412=_response(role='Operator'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED),
            [Result.FAIL])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_verify_channel_broken_not_tested(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        # Exception-synthesized 600 response: no verification verdict
        gets = self.happy_path_gets(
            verify_after_412=_response(status_code=600))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED),
            [Result.NOT_TESTED])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_write_not_evaluated_not_tested(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        patches = self.happy_path_patches()
        patches[0] = _response(status_code=401)  # session dropped
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(self.sut, 'patch', side_effect=patches):
            etags.test_etags(self.sut)
        results = self.result(Assertion.PROTO_ETAG_IF_MATCH_ENFORCED)
        self.assertEqual(results[0], Result.NOT_TESTED)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_412_WRITE_NOT_APPLIED),
            [Result.NOT_TESTED])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_accepted_write_not_observable_fails(self, mock_race,
                                                 mock_sleep):
        mock_race.return_value = self.happy_race()
        # the accepted write's role never shows up on the read-back
        gets = self.happy_path_gets(
            verify_new_role=_response(role='ReadOnly'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertIn(Result.FAIL,
                      self.result(Assertion.PROTO_ETAG_IF_MATCH_ENFORCED))
        # downstream write tests cannot run without an applied write
        self.assertEqual(self.result(Assertion.PROTO_ETAG_LOST_UPDATE),
                         [Result.NOT_TESTED])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_unstable_etag_warns(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        gets = self.happy_path_gets(
            stability=_response(etag='"E1b"', body_etag='"E1b"',
                                role='ReadOnly'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_STABLE_WITHOUT_MODIFICATION),
            [Result.WARN])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_header_property_mismatch_warns(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        gets = self.happy_path_gets(
            initial=_response(etag='"E1"', body_etag='"E1-other"',
                              role='ReadOnly'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_HEADER_AND_PROPERTY),
            [Result.WARN])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_conditional_get_unsupported_warns(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        gets = self.happy_path_gets(
            conditional_get=_response(etag='"E1"', body_etag='"E1"',
                                      role='ReadOnly'))  # full body
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(self.result(Assertion.PROTO_ETAG_CONDITIONAL_GET),
                         [Result.WARN])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_etag_not_rotated_warns(self, mock_race, mock_sleep):
        mock_race.return_value = self.happy_race()
        gets = self.happy_path_gets(
            rotation=_response(etag='"E1"', body_etag='"E1"',
                               role='Operator'))  # unchanged
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_ROTATES_ON_WRITE),
            [Result.WARN])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._probe_tag_resolution')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_two_winners_one_incomplete_fails(self, mock_race,
                                                   mock_probe, mock_sleep):
        # Two accepted preconditions fail even when another writer
        # never completed
        mock_race.return_value = [
            _response(), _response(status_code=202),
            _response(status_code=412), None]
        mock_probe.return_value = ('rotates', 900)
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS),
            [Result.FAIL])
        msg = self.sut.results[Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS][0]['msg']
        self.assertIn('closest it could space two writes was 900 ms', msg)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._probe_tag_resolution')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_two_winners_coarse_tag_names_resolution(self, mock_race,
                                                          mock_probe,
                                                          mock_sleep):
        mock_race.return_value = [
            _response(), _response(),
            _response(status_code=412), _response(status_code=412)]
        mock_probe.return_value = ('coarse', 120)
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS),
            [Result.FAIL])
        msg = self.sut.results[Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS][0]['msg']
        self.assertIn('two writes 120 ms apart', msg)
        self.assertNotIn('not atomic', msg)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._probe_tag_resolution')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_two_winners_opaque_tag_is_not_atomic(self, mock_race,
                                                       mock_probe,
                                                       mock_sleep):
        # The race tag is opaque and the diagnose read carries the
        # service clock: not a clock value, so the service let two
        # writers through and the probe is not needed
        mock_race.return_value = [
            _response(), _response(),
            _response(status_code=412), _response(status_code=412)]
        gets = self.happy_path_gets(
            verify_race_winner=_response(role='Operator',
                                         date=DATE_HEADER))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS),
            [Result.FAIL])
        msg = self.sut.results[Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS][0]['msg']
        self.assertIn('are not atomic', msg)
        self.assertEqual(mock_probe.call_count, 0)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._probe_tag_resolution')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_two_winners_clock_tag_is_named(self, mock_race,
                                                 mock_probe, mock_sleep):
        # The race tag matches the service clock, so a rotating probe
        # outcome is promoted to the clock diagnosis
        mock_race.return_value = [
            _response(), _response(),
            _response(status_code=412), _response(status_code=412)]
        mock_probe.return_value = ('rotates', 900)
        gets = self.happy_path_gets(
            race_read=_response(etag=DATE_EPOCH_ETAG,
                                body_etag=DATE_EPOCH_ETAG,
                                role='Operator'),
            verify_race_winner=_response(role='Operator',
                                         date=DATE_HEADER))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        msg = self.sut.results[Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS][0]['msg']
        self.assertIn('tracks the service clock', msg)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_202_winner_warns(self, mock_race, mock_sleep):
        mock_race.return_value = [
            _response(status_code=412), _response(status_code=202),
            _response(status_code=412), _response(status_code=412)]
        # write not yet observable
        gets = self.happy_path_gets(
            verify_race_winner=_response(role='Operator'))
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS),
            [Result.WARN])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_incomplete_not_tested(self, mock_race, mock_sleep):
        mock_race.return_value = [None, None, None, None]
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        results = self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS)
        self.assertEqual(results, [Result.NOT_TESTED])

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_all_412_fails(self, mock_race, mock_sleep):
        mock_race.return_value = [
            _response(status_code=412), _response(status_code=412),
            _response(status_code=412), _response(status_code=412)]
        with mock.patch.object(
                self.sut, 'get', side_effect=self.happy_path_gets()), \
                mock.patch.object(
                    self.sut, 'patch',
                    side_effect=self.happy_path_patches()):
            etags.test_etags(self.sut)
        self.assertEqual(
            self.result(Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS),
            [Result.FAIL])

    @mock.patch('redfish_protocol_validator.etags.requests.Session')
    def test_race_writers_fire_together(self, mock_session_cls):
        # every writer gets its own session, sends the same If-Match and
        # role, and closes its connection
        sessions = []

        def make_session():
            session = mock.MagicMock()
            session.get.return_value = _response()
            session.patch.return_value = _response(status_code=412)
            sessions.append(session)
            return session

        mock_session_cls.side_effect = make_session
        responses = etags._race_conditional_writes(
            self.sut, ACCT_URI, '"E1"', 'ReadOnly')
        self.assertEqual(len(responses), etags.RACE_WRITERS)
        self.assertEqual(len(sessions), etags.RACE_WRITERS)
        for response in responses:
            self.assertEqual(response.status_code, 412)
        for session in sessions:
            session.patch.assert_called_once_with(
                self.sut.rhost + ACCT_URI,
                json={'RoleId': 'ReadOnly'},
                headers={'If-Match': '"E1"'}, timeout=30)
            session.close.assert_called_once_with()

    @mock.patch('redfish_protocol_validator.etags.requests.Session')
    def test_race_writer_exception_yields_none(self, mock_session_cls):
        # a raising writer becomes None instead of hanging the barrier
        def make_session():
            session = mock.MagicMock()
            session.get.return_value = _response()
            session.patch.side_effect = requests.ConnectionError('down')
            return session

        mock_session_cls.side_effect = make_session
        responses = etags._race_conditional_writes(
            self.sut, ACCT_URI, '"E1"', 'ReadOnly')
        self.assertEqual(responses, [None] * etags.RACE_WRITERS)

    def test_account_setup_failed_not_tested(self):
        self.mock_accounts.add_account.return_value = (None, None, None)
        etags.test_etags(self.sut)
        for assertion in etags.ETAG_ASSERTIONS:
            self.assertEqual(self.result(assertion), [Result.NOT_TESTED],
                             'assertion %s' % assertion.name)
        self.assertEqual(self.mock_accounts.delete_account.call_count, 0)

    def test_no_etag_header_not_tested(self):
        with mock.patch.object(
                self.sut, 'get',
                side_effect=[_response(body_etag='"E1"', role='ReadOnly')]):
            etags.test_etags(self.sut)
        for assertion in etags.ETAG_ASSERTIONS:
            self.assertEqual(self.result(assertion), [Result.NOT_TESTED],
                             'assertion %s' % assertion.name)
        self.assertEqual(self.mock_accounts.delete_account.call_count, 1)

    @mock.patch('redfish_protocol_validator.etags.time.sleep')
    def test_no_role_property_write_tests_not_tested(self, mock_sleep):
        gets = [_response(etag='"E1"', body_etag='"E1"'),
                _response(etag='"E1"', body_etag='"E1"'),
                _response(status_code=304)]
        with mock.patch.object(self.sut, 'get', side_effect=gets):
            etags.test_etags(self.sut)
        for assertion in [Assertion.PROTO_ETAG_IF_MATCH_ENFORCED,
                          Assertion.PROTO_ETAG_LOST_UPDATE,
                          Assertion.SEC_ACCOUNTS_SUPPORT_ETAGS]:
            self.assertEqual(self.result(assertion), [Result.NOT_TESTED],
                             'assertion %s' % assertion.name)
        # the read-only checks still run
        self.assertEqual(
            self.result(Assertion.PROTO_ETAG_HEADER_AND_PROPERTY),
            [Result.PASS])
        self.assertEqual(self.mock_accounts.delete_account.call_count, 1)

    def probe_with_tags(self, tags):
        """Run the probe over a scripted sequence of tag reads."""
        gets = [_response(etag=t, body_etag=t, role='ReadOnly')
                for t in tags]
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(self.sut, 'patch',
                                  return_value=_response()):
            return etags._probe_tag_resolution(self.sut, ACCT_URI)

    def test_probe_tag_resolution_coarse(self):
        # two consecutive writes produce the same tag
        outcome, gap = self.probe_with_tags(['"T0"', '"T1"', '"T1"'])
        self.assertEqual(outcome, 'coarse')
        self.assertIsInstance(gap, int)

    def test_probe_tag_resolution_rotates(self):
        tags = ['"T%d"' % i for i in range(1 + 2 * etags.PROBE_PAIRS)]
        outcome, gap = self.probe_with_tags(tags)
        self.assertEqual(outcome, 'rotates')
        self.assertIsInstance(gap, int)

    def test_probe_tag_resolution_coarse_on_later_pair(self):
        # first pair rotates, second pair repeats a tag
        outcome, _ = self.probe_with_tags(
            ['"T0"', '"T1"', '"T2"', '"T3"', '"T3"'])
        self.assertEqual(outcome, 'coarse')

    def test_probe_tag_resolution_inconclusive_on_rejected_write(self):
        gets = [_response(etag='"T1"', body_etag='"T1"', role='ReadOnly')]
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(self.sut, 'patch',
                                  return_value=_response(status_code=412)):
            outcome, _ = etags._probe_tag_resolution(self.sut, ACCT_URI)
        self.assertEqual(outcome, 'inconclusive')

    def test_probe_flips_the_role_away_and_back(self):
        # a coarse pair ends the probe after exactly two writes
        tags = ['"T0"', '"T1"', '"T1"']
        gets = [_response(etag=t, body_etag=t, role='ReadOnly')
                for t in tags]
        with mock.patch.object(self.sut, 'get', side_effect=gets), \
                mock.patch.object(self.sut, 'patch',
                                  return_value=_response()) as mock_patch:
            etags._probe_tag_resolution(self.sut, ACCT_URI)
        roles = [kwargs['json']['RoleId']
                 for _, kwargs in mock_patch.call_args_list[:2]]
        self.assertEqual(roles, ['Operator', 'ReadOnly'])


if __name__ == '__main__':
    unittest.main()
