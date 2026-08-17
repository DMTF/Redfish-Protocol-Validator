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


def _response(status_code=200, etag=None, body_etag=None, role=None):
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status_code
    # Mirror requests: raise_for_status raises only for 4xx and 5xx, so
    # ok is True for the 600 the SUT synthesizes from a transport
    # exception
    resp.ok = not (400 <= status_code < 600)
    headers = {'Content-Type': 'application/json'}
    if etag is not None:
        headers['ETag'] = etag
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

    def verdict(self, statuses, race_etag='"E1"'):
        return etags._race_verdict(statuses, etags._classify_race(statuses),
                                   race_etag)

    def test_race_verdict_clean_winner_defers(self):
        self.assertIsNone(self.verdict([412, 200, 412, 412]))

    def test_race_verdict_multi_winner_fails(self):
        result, msg = self.verdict([200, 200, 412, 412])
        self.assertEqual(result, Result.FAIL)
        self.assertIn('at most one conditional write may succeed', msg)

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
    @mock.patch('redfish_protocol_validator.etags._race_conditional_writes')
    def test_race_two_winners_one_incomplete_fails(self, mock_race,
                                                   mock_sleep):
        # Two accepted preconditions fail even when another writer
        # never completed
        mock_race.return_value = [
            _response(), _response(status_code=202),
            _response(status_code=412), None]
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
        self.assertIn('at most one conditional write may succeed', msg)

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


if __name__ == '__main__':
    unittest.main()
