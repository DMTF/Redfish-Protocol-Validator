# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
from urllib.parse import urlparse

import requests

from redfish_protocol_validator import accounts
from redfish_protocol_validator.constants import RequestType
from redfish_protocol_validator.system_under_test import SystemUnderTest


def bad_login(sut: SystemUnderTest):
    """Try to login with bad credentials"""
    # Keep these invalid basic auth attempts to a minimum. Some services will
    # block clients after a number of failed attempts.
    # e.g. "Login attempt alert for rfpv66af from 192.168.1.101 using REDFISH,
    #       IP will be blocked for 600 seconds."
    payload = {
        'UserName': accounts.new_username(set()),
        'Password': accounts.new_password(sut)
    }
    headers = {
        'OData-Version': '4.0'
    }
    response = requests.post(sut.rhost + sut.sessions_uri, json=payload,
                             headers=headers, verify=sut.verify)
    sut.add_response(sut.sessions_uri, response,
                     request_type=RequestType.BAD_AUTH)


def create_session(sut: SystemUnderTest):
    payload = {
        'UserName': sut.username,
        'Password': sut.password
    }
    headers = {
        'OData-Version': '4.0',
        'Content-Type': 'application/json;charset=utf-8'
    }
    response = requests.post(sut.rhost + sut.sessions_uri, json=payload,
                             headers=headers, verify=sut.verify)
    if not response.ok:
        logging.warning('session POST status: %s, response: %s' % (
            response.status_code, response.text))
    # creating a session with NO_AUTH is also NORMAL, so register both types
    sut.add_response(sut.sessions_uri, response,
                     request_type=RequestType.NORMAL)
    sut.add_response(sut.sessions_uri, response,
                     request_type=RequestType.NO_AUTH)
    new_session_uri = None
    token = None
    if response.ok:
        location = response.headers.get('Location')
        if location:
            new_session_uri = urlparse(location).path
        token = response.headers.get('X-Auth-Token')
    return new_session_uri, token


def delete_session(sut: SystemUnderTest, session, session_uri,
                   request_type=RequestType.NORMAL):
    response = session.delete(sut.rhost + session_uri)
    sut.add_response(session_uri, response, request_type=request_type)
    return response


def no_auth_session(sut: SystemUnderTest):
    session = requests.Session()
    session.verify = sut.verify
    return session
