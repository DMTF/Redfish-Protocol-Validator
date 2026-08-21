# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import argparse
import configparser
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning
from http.client import HTTPConnection

from redfish_protocol_validator import etags
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

tool_version = '1.3.1'


def load_config(config_file):
    """
    Loads configuration from a config.ini file

    Args:
        config_file: Path to the configuration file

    Returns:
        A dictionary containing the configuration values
    """
    config = configparser.ConfigParser()
    config_values = {}

    try:
        if not os.path.isfile(config_file):
            return config_values
        
        config.read(config_file)
        
        # Authentication section
        if config.has_section('Authentication'):
            if config.has_option('Authentication', 'user'):
                user = config.get('Authentication', 'user').strip()
                if user:
                    config_values['user'] = user
            if config.has_option('Authentication', 'password'):
                password = config.get('Authentication', 'password').strip()
                if password:
                    config_values['password'] = password
        
        # Connection section
        if config.has_section('Connection'):
            if config.has_option('Connection', 'rhost'):
                rhost = config.get('Connection', 'rhost').strip()
                if rhost:
                    config_values['rhost'] = rhost
            if config.has_option('Connection', 'no-cert-check'):
                config_values['no_cert_check'] = config.getboolean('Connection', 'no-cert-check')
            if config.has_option('Connection', 'ca-bundle'):
                ca_bundle = config.get('Connection', 'ca-bundle').strip()
                if ca_bundle:
                    config_values['ca_bundle'] = ca_bundle
            if config.has_option('Connection', 'avoid-http-redirect'):
                config_values['avoid_http_redirect'] = config.getboolean('Connection', 'avoid-http-redirect')
        
        # Logging section
        if config.has_section('Logging'):
            if config.has_option('Logging', 'log-level'):
                log_level = config.get('Logging', 'log-level').strip()
                if log_level:
                    config_values['log_level'] = log_level
        
        # Reporting section
        if config.has_section('Reporting'):
            if config.has_option('Reporting', 'report-dir'):
                report_dir = config.get('Reporting', 'report-dir').strip()
                if report_dir:
                    config_values['report_dir'] = report_dir
            if config.has_option('Reporting', 'report-type'):
                report_type = config.get('Reporting', 'report-type').strip()
                if report_type:
                    config_values['report_type'] = report_type
        
    except Exception as err:
        print("WARNING: Error reading config file '{}': {}".format(config_file, err))
        return {}
    
    return config_values


def perform_tests(sut: SystemUnderTest):
    """Perform the protocol validation tests on the resources."""
    protocol_details.test_protocol_details(sut)
    service_requests.test_service_requests(sut)
    service_responses.test_service_responses(sut)
    service_details.test_service_details(sut)
    security_details.test_security_details(sut)
    etags.test_etags(sut)


def main():
    parser = argparse.ArgumentParser(
        description='Validate the protocol conformance of a Redfish service')
    parser.add_argument('--version', action='version',
                        version='Redfish-Protocol-Validator %s' % tool_version)
    parser.add_argument('--config', '-c', type=str, default='config.ini',
                        help='path to configuration file; defaults to '
                             '"config.ini" in current directory')
    parser.add_argument('--user', '-u', type=str,
                        help='the username for authentication')
    parser.add_argument('--password', '-p', type=str,
                        help='the password for authentication')
    parser.add_argument('--rhost', '-r', type=str,
                        help='address of the Redfish service (with scheme)')
    parser.add_argument('--log-level', type=str,
                        help='the logging level (default: WARNING)',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--report-dir', type=str,
                        help='the directory for generated report files '
                             '(default: "reports")')
    parser.add_argument('--report-type', choices=['html', 'tsv', 'both'],
                        help='the type of report to generate: html, tsv, or '
                             'both (default: both)')
    parser.add_argument('--avoid-http-redirect', action='store_true',
                        help='avoid attempts to generate HTTP redirects for '
                             'services that do not support HTTP')
    cert_g = parser.add_mutually_exclusive_group()
    cert_g.add_argument('--no-cert-check', action='store_true',
                        help='disable verification of host SSL certificates')
    cert_g.add_argument('--ca-bundle', type=str,
                        help='the file or directory containing trusted CAs')
    args = parser.parse_args()

    # Load configuration from file
    config_values = load_config(args.config)

    # Required arguments: rhost, user, password
    if args.rhost is None:
        args.rhost = config_values.get('rhost')
    if args.user is None:
        args.user = config_values.get('user')
    if args.password is None:
        args.password = config_values.get('password')
    
    # Check if required arguments are present
    if args.rhost is None:
        print("ERROR: Redfish service host is required (provide via --rhost or config file)")
        sys.exit(1)
    if args.user is None:
        print("ERROR: Username is required (provide via --user or config file)")
        sys.exit(1)
    if args.password is None:
        print("ERROR: Password is required (provide via --password or config file)")
        sys.exit(1)
    
    # Optional string arguments
    if args.log_level is None:
        args.log_level = config_values.get('log_level', 'WARNING')
    if args.report_dir is None:
        args.report_dir = config_values.get('report_dir', 'reports')
    if args.report_type is None:
        args.report_type = config_values.get('report_type', 'both')
    if args.ca_bundle is None:
        args.ca_bundle = config_values.get('ca_bundle')
    
    # Optional Boolean arguments
    if not args.no_cert_check and 'no_cert_check' in config_values:
        args.no_cert_check = config_values['no_cert_check']
    if not args.avoid_http_redirect and 'avoid_http_redirect' in config_values:
        args.avoid_http_redirect = config_values['avoid_http_redirect']

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
