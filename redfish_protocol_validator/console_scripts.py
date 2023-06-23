# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning
from http.client import HTTPConnection

from redfish_protocol_validator import protocol_details
from redfish_protocol_validator import report
from redfish_protocol_validator import resources
from redfish_protocol_validator import security_details
from redfish_protocol_validator import service_details
from redfish_protocol_validator import service_requests
from redfish_protocol_validator import service_responses
from redfish_protocol_validator import sessions
from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

tool_version = '1.1.8'


def perform_tests(sut: SystemUnderTest):
    """Perform the protocol validation tests on the resources."""
    protocol_details.test_protocol_details(sut)
    service_requests.test_service_requests(sut)
    service_responses.test_service_responses(sut)
    service_details.test_service_details(sut)
    security_details.test_security_details(sut)


def main():
    parser = argparse.ArgumentParser(
        description='Validate the protocol conformance of a Redfish service')
    parser.add_argument('--version', action='version',
                        version='Redfish-Protocol-Validator %s' % tool_version)
    parser.add_argument('--user', '-u', type=str, required=True,
                        help='the username for authentication')
    parser.add_argument('--password', '-p', type=str, required=True,
                        help='the password for authentication')
    parser.add_argument('--rhost', '-r', type=str, required=True,
                        help='address of the Redfish service (with scheme)')
    parser.add_argument('--log-level', type=str, default='WARNING',
                        help='the logging level (default: WARNING)',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--report-dir', type=str, default='reports',
                        help='the directory for generated report files '
                             '(default: "reports")')
    parser.add_argument('--report-type', choices=['html', 'tsv', 'both'],
                        help='the type of report to generate: html, tsv, or '
                             'both (default: both)', default='both')
    parser.add_argument('--avoid-http-redirect', action='store_true',
                        help='avoid attempts to generate HTTP redirects for '
                             'services that do not support HTTP')
    cert_g = parser.add_mutually_exclusive_group()
    cert_g.add_argument('--no-cert-check', action='store_true',
                        help='disable verification of host SSL certificates')
    cert_g.add_argument('--ca-bundle', type=str,
                        help='the file or directory containing trusted CAs')
    args = parser.parse_args()

    # set logging level
    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(level=log_level)
    if log_level == logging.DEBUG:
        HTTPConnection.debuglevel = 1

    # set up cert verify option
    verify = args.ca_bundle if args.ca_bundle else not args.no_cert_check
    if args.no_cert_check:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # create report directory if needed
    report_dir = Path(args.report_dir)
    if not report_dir.is_dir():
        report_dir.mkdir(parents=True)

    sut = SystemUnderTest(args.rhost, args.user, args.password, verify=verify)
    sut.set_avoid_http_redirect(args.avoid_http_redirect)
    sut.login()
    resources.read_target_resources(sut, func=resources.get_default_resources)
    no_auth_session = sessions.no_auth_session(sut)
    resources.read_uris_no_auth(sut, no_auth_session)
    resources.data_modification_requests(sut)
    resources.data_modification_requests_no_auth(sut, no_auth_session)
    resources.unsupported_requests(sut)
    resources.basic_auth_requests(sut)
    resources.http_requests(sut)
    resources.bad_auth_requests(sut)
    sessions.bad_login(sut)
    perform_tests(sut)
    sut.logout()
    utils.print_summary(sut)
    current_time = datetime.now()
    print('Report output:')
    report.json_results(sut, report_dir, current_time, tool_version)
    if args.report_type in ('tsv', 'both'):
        print(report.tsv_report(sut, report_dir, current_time))
    if args.report_type in ('html', 'both'):
        print(report.html_report(sut, report_dir, current_time, tool_version))
    # exit with status 1 if any assertions failed, 0 otherwise
    sys.exit(int(sut.summary_count(Result.FAIL) > 0))


if __name__ == "__main__":
    main()
