# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
import random
import string
from urllib.parse import urlparse

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import RequestType, ResourceType
from redfish_protocol_validator.system_under_test import SystemUnderTest


def get_user_names(sut: SystemUnderTest, session,
                   request_type=RequestType.NORMAL):
    users = set()
    response = sut.get_response('GET', sut.accounts_uri)
    if response.status_code == requests.codes.OK:
        data = response.json()
        uris = [m.get('@odata.id') for m in data.get('Members', []) if
                m.get('@odata.id')]
        responses = sut.get_responses_by_method(
            'GET', resource_type=ResourceType.MANAGER_ACCOUNT)
        for uri in uris:
            if uri in responses:
                response = responses[uri]
            else:
                response = session.get(sut.rhost + uri)
                sut.add_response(uri, response,
                                 resource_type=ResourceType.MANAGER_ACCOUNT,
                                 request_type=request_type)
            if response.status_code == requests.codes.OK:
                data = response.json()
                user = data.get('UserName')
                if user:
                    users.add(user)
    logging.debug('Account usernames: %s' % users)
    return users


def get_available_roles(sut: SystemUnderTest, session,
                        request_type=RequestType.NORMAL):
    roles = set()
    response = sut.get_response('GET', sut.roles_uri)
    if response.status_code == requests.codes.OK:
        data = response.json()
        uris = [m.get('@odata.id') for m in data.get('Members', []) if
                m.get('@odata.id')]
        responses = sut.get_responses_by_method(
            'GET', resource_type=ResourceType.ROLE)
        for uri in uris:
            if uri in responses:
                response = responses[uri]
            else:
                response = session.get(sut.rhost + uri)
                sut.add_response(uri, response,
                                 resource_type=ResourceType.ROLE,
                                 request_type=request_type)
            if response.status_code == requests.codes.OK:
                data = response.json()
                role = data.get('Id')
                if role:
                    roles.add(role)
    logging.debug('Available roles: %s' % roles)
    return roles


def select_standard_role(sut: SystemUnderTest, session,
                         request_type=RequestType.NORMAL):
    roles = get_available_roles(sut, session, request_type=request_type)
    role = None
    if 'ReadOnly' in roles:
        role = 'ReadOnly'
    if not role:
        logging.error('Predefined role "ReadOnly" not found')
    logging.debug('Role selected for account creation: %s' % role)
    return role


def new_username(existing_users):
    while True:
        user = 'rfpv%04x' % random.randrange(2 ** 16)  # ex: 'rfpvc91c'
        if user not in existing_users:
            break
    return user


def new_password(sut: SystemUnderTest, length=16, upper=1, lower=1,
                 digits=1, symbols=1):
    # Get the min and max password length and override 'length' if needed
    # Use either limit if one is specified
    response = sut.get_response('GET', sut.account_service_uri)
    try:
        if response.ok:
            data = response.json()
            if 'MinPasswordLength' in data and length < data['MinPasswordLength']:
                length = data['MinPasswordLength']
            elif 'MaxPasswordLength' in data and length > data['MaxPasswordLength']:
                length = data['MaxPasswordLength']
    except:
        pass

    ascii_symbols = '_-.'
    pwd = random.sample(string.ascii_uppercase, upper)
    pwd.extend(random.sample(string.ascii_lowercase, lower))
    pwd.extend(random.sample(string.digits, digits))
    pwd.extend(random.sample(ascii_symbols, symbols))
    pwd.extend(random.sample(string.ascii_letters,
                             length - upper - lower - digits - symbols))
    random.shuffle(pwd)
    pwd = ''.join(pwd)
    sut.add_priv_info(pwd)
    return pwd


def find_empty_account_slot(sut: SystemUnderTest, session,
                            request_type=RequestType.NORMAL):
    response = sut.get_response('GET', sut.accounts_uri)
    data = response.json()
    uris = [m.get('@odata.id') for m in data.get('Members', []) if
            m.get('@odata.id')]
    responses = sut.get_responses_by_method(
        'GET', resource_type=ResourceType.MANAGER_ACCOUNT)
    if uris:
        # first slot may be reserved, so move to end of list
        uris += [uris.pop(0)]
    for uri in uris:
        if uri in responses:
            response = responses[uri]
        else:
            response = session.get(sut.rhost + uri)
            sut.add_response(uri, response,
                             resource_type=ResourceType.MANAGER_ACCOUNT,
                             request_type=request_type)
        if response.status_code == requests.codes.OK:
            data = response.json()
            if data.get('UserName') == '' and not data.get('Enabled', True):
                return uri
    return None


def add_account_via_patch(sut: SystemUnderTest, session, user, role, password,
                          request_type=RequestType.NORMAL):
    uri = find_empty_account_slot(sut, session, request_type=request_type)
    if not uri:
        logging.error('No empty account slot found to create new account')
        return None, None, None
    payload = {'UserName': user,
               'Password': password}
    if role:
        payload['RoleId'] = role
    headers = utils.get_etag_header(sut, session, uri)
    response = session.patch(sut.rhost + uri, json=payload, headers=headers)
    sut.add_response(uri, response, resource_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=request_type)
    success = response.status_code == requests.codes.OK
    if success:
        response = session.get(sut.rhost + uri)
        if response.ok:
            # Enable the account if it not already enabled
            data = response.json()
            if 'Enabled' in data and data['Enabled'] is False:
                headers = utils.get_etag_header(sut, session, uri)
                payload = {'Enabled': True}
                session.patch(sut.rhost + uri, json=payload,
                              headers=headers)
        sut.add_response(uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=request_type)
    else:
        uri = None
    return user, password, uri


def add_account(sut: SystemUnderTest, session,
                request_type=RequestType.NORMAL):
    if not sut.accounts_uri:
        logging.error('No accounts collection found')
        return None, None, None
    response = sut.get_response('GET', sut.accounts_uri)
    if response.status_code != requests.codes.OK:
        logging.error('Accounts collection could not be read')
        return None, None, None

    users = get_user_names(sut, session, request_type=request_type)
    user = new_username(users)
    role = select_standard_role(sut, session)
    password = new_password(sut)

    headers = response.headers
    methods = []
    if 'Allow' in headers:
        methods = [m.strip() for m in headers.get('Allow').split(',')]

    payload = {'UserName': user, 'Password': password}
    if role:
        payload['RoleId'] = role
    response = session.post(sut.rhost + sut.accounts_uri, json=payload)
    sut.add_response(sut.accounts_uri, response, request_type=request_type)

    new_acct_uri = None
    success = response.status_code == requests.codes.CREATED
    if success:
        location = response.headers.get('Location')
        if location:
            new_acct_uri = urlparse(location).path
        else:
            new_acct_uri = response.json().get('@odata.id')
        response = session.get(sut.rhost + new_acct_uri)
        sut.add_response(new_acct_uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=request_type)
    elif (response.status_code == requests.codes.METHOD_NOT_ALLOWED
          or 'POST' not in methods):
        return add_account_via_patch(sut, session, user, role, password,
                                     request_type=request_type)
    return user, password, new_acct_uri


def patch_account(sut: SystemUnderTest, session, acct_uri,
                  request_type=RequestType.NORMAL):

    if request_type == RequestType.NORMAL:
        # patch several props, mix of updatable and non-updatable
        pwd = new_password(sut)
        payload = {'Password': pwd, 'BogusProp': 'foo'}
        headers = utils.get_etag_header(sut, session, acct_uri)
        response = session.patch(sut.rhost + acct_uri, json=payload,
                                 headers=headers)
        if response.ok:
            new_pwd = pwd
        sut.add_response(acct_uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=RequestType.PATCH_MIXED_PROPS)
        # patch a single property that can never be updated
        payload = {'BogusProp': 'foo'}
        headers = utils.get_etag_header(sut, session, acct_uri)
        response = session.patch(sut.rhost + acct_uri, json=payload,
                                 headers=headers)
        sut.add_response(acct_uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=RequestType.PATCH_BAD_PROP)
        # patch only OData annotations
        odata_id = (acct_uri.rstrip('/') if acct_uri.endswith('/')
                    else acct_uri + '/')
        payload = {'@odata.id': odata_id}
        headers = utils.get_etag_header(sut, session, acct_uri)
        response = session.patch(sut.rhost + acct_uri, json=payload,
                                 headers=headers)
        sut.add_response(acct_uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=RequestType.PATCH_ODATA_PROPS)

    new_pwd = None
    # patch with proper ETag
    pwd = new_password(sut)
    payload = {'Password': pwd}
    headers = utils.get_etag_header(sut, session, acct_uri)
    response = session.patch(sut.rhost + acct_uri, json=payload,
                             headers=headers)
    if response.ok:
        new_pwd = pwd
    sut.add_response(acct_uri, response,
                     resource_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=request_type)
    if request_type == RequestType.NORMAL and 'If-Match' in headers:
        # patch with invalid ETag, which should fail
        pwd = new_password(sut)
        payload = {'Password': pwd}
        new_headers = utils.get_etag_header(sut, session, acct_uri)
        bad_headers = {'If-Match': new_headers['If-Match'] + 'foobar'}
        r = session.patch(sut.rhost + acct_uri, json=payload,
                          headers=bad_headers)
        if r.ok:
            new_pwd = pwd
        sut.add_response(acct_uri, r,
                         resource_type=ResourceType.MANAGER_ACCOUNT,
                         request_type=RequestType.BAD_ETAG)
    return new_pwd


def delete_account_via_patch(sut: SystemUnderTest, session, user, acct_uri,
                             request_type=RequestType.NORMAL):
    response = sut.get_response('GET', acct_uri)
    if response.status_code == requests.codes.OK:
        data = response.json()
        if data and data.get('UserName') == user:
            payload = {'UserName': ''}
            if data.get('Enabled', False):
                payload['Enabled'] = False
            headers = utils.get_etag_header(sut, session, acct_uri)
            response = session.patch(sut.rhost + acct_uri, json=payload,
                                     headers=headers)
            sut.add_response(acct_uri, response,
                             resource_type=ResourceType.MANAGER_ACCOUNT,
                             request_type=request_type)
        else:
            logging.error('Delete account via PATCH skipped; username %s '
                          'did not match expected username %s' %
                          (data.get('UserName'), user))
    else:
        logging.error('Delete account via PATCH skipped; could not read '
                      'account uri %s' % acct_uri)


def delete_account(sut: SystemUnderTest, session, user, acct_uri,
                   request_type=RequestType.NORMAL):
    response = sut.get_response('GET', acct_uri)
    headers = response.headers
    if 'Allow' in headers:
        methods = [m.strip() for m in headers.get('Allow').split(',')]
        if 'DELETE' not in methods:
            # if Allow header present and DELETE not listed, delete via PATCH
            delete_account_via_patch(sut, session, user, acct_uri,
                                     request_type=request_type)
            return
    response = session.delete(sut.rhost + acct_uri)
    sut.add_response(acct_uri, response,
                     resource_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=request_type)
    if response.status_code == requests.codes.METHOD_NOT_ALLOWED:
        delete_account_via_patch(sut, session, user, acct_uri,
                                 request_type=request_type)


def password_change_required(sut: SystemUnderTest, session, user, password,
                             uri, data, etag):
    if 'PasswordChangeRequired' not in data:
        return
    # set PasswordChangeRequired if not already set or if the account needs to be enabled
    account_enabled = data.get('Enabled', True)
    if data['PasswordChangeRequired'] is False or not account_enabled:
        payload = {
            'PasswordChangeRequired': True
        }
        if not account_enabled:
            payload['Enabled'] = True
        headers = {'If-Match': etag} if etag else {}
        response = session.patch(sut.rhost + uri, json=payload,
                                 headers=headers)
        sut.add_response(uri, response,
                         resource_type=ResourceType.MANAGER_ACCOUNT)
        if not response.ok:
            return
    # create session as new user
    payload = {
        'UserName': user,
        'Password': password
    }
    headers = {
        'OData-Version': '4.0'
    }
    response = requests.post(sut.rhost + sut.sessions_uri, json=payload,
                             headers=headers, verify=sut.verify)
    sut.add_response(sut.sessions_uri, response,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
    # GET the account
    response = requests.get(sut.rhost + uri, auth=(user, password),
                            headers=headers)
    etag = utils.get_response_etag(response)
    sut.add_response(uri, response, resource_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
    # try to get protected resource
    response = requests.get(sut.rhost + sut.sessions_uri,
                            auth=(user, password), headers=headers)
    sut.add_response(sut.sessions_uri, response,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
    # change password
    payload = {'Password': new_password(sut)}
    if etag:
        headers['If-Match'] = etag
    response = requests.patch(uri, auth=(user, password), json=payload,
                              headers=headers)
    sut.add_response(uri, response,
                     resource_type=ResourceType.MANAGER_ACCOUNT,
                     request_type=RequestType.PWD_CHANGE_REQUIRED)
