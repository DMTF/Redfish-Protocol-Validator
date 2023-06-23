# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import logging
from urllib.parse import urlparse

import requests

from redfish_protocol_validator.utils import redfish_version_to_tuple
from redfish_protocol_validator.constants import RequestType, Result


class SystemUnderTest(object):
    def __init__(self, rhost, username, password, verify=True):
        self._rhost = rhost
        self._username = username
        self._password = password
        self._version_string = None
        self._version_tuple = None
        self._product = None
        self._manufacturer = None
        self._model = None
        self._firmware_version = None
        self._service_uuid = None
        self._session = None
        self._sessions_uri = None
        self._active_session_uri = None
        self._active_session_key = None
        self._systems_uri = None
        self._managers_uri = None
        self._chassis_uri = None
        self._account_service_uri = None
        self._accounts_uri = None
        self._roles_uri = None
        self._event_service_uri = None
        self._cert_service_uri = None
        self._sse_uri = None
        self._subscriptions_uri = None
        self._event_dest_uri = None
        self._priv_registry = None
        self._mgr_net_proto_uri = None
        self._ssdp_enabled = False
        self._ssdp_services = {}
        self._results = {}
        self._responses = {}
        self._typed_responses = {}
        self._verify = verify
        self._priv_info = set()
        self._priv_info.add(password)
        self._users = {}
        self._roles = {}
        self._cert_coll = {}
        self._supported_query_params = {}
        self._avoid_http_redirect = False
        self._summary = {
            Result.PASS: 0,
            Result.WARN: 0,
            Result.FAIL: 0,
            Result.NOT_TESTED: 0
        }
        parsed = urlparse(rhost)
        self._scheme = parsed.scheme

    @property
    def rhost(self):
        return self._rhost

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def scheme(self):
        return self._scheme

    def set_version(self, version):
        try:
            self._version_tuple = redfish_version_to_tuple(version)
            self._version_string = version
        except Exception:
            logging.warning('Redfish protocol version string "%s" could not '
                            'be parsed; assuming version 1.0.0' % version)
            self._version_tuple = redfish_version_to_tuple('1.0.0')
            self._version_string = '1.0.0'

    @property
    def version_string(self):
        return self._version_string

    @property
    def version_tuple(self):
        return self._version_tuple

    @property
    def verify(self):
        return self._verify

    def set_product(self, product):
        self._product = product

    @property
    def product(self):
        return self._product

    def set_manufacturer(self, manufacturer):
        self._manufacturer = manufacturer

    @property
    def manufacturer(self):
        return self._manufacturer

    def set_model(self, model):
        self._model = model

    @property
    def model(self):
        return self._model

    def set_firmware_version(self, firmware_version):
        self._firmware_version = firmware_version

    @property
    def firmware_version(self):
        return self._firmware_version

    def _set_session(self, session):
        self._session = session

    def set_service_uuid(self, uuid):
        self._service_uuid = uuid.lower() if uuid else None

    @property
    def service_uuid(self):
        return self._service_uuid

    @property
    def session(self):
        return self._session

    def set_sessions_uri(self, uri):
        self._sessions_uri = uri

    @property
    def sessions_uri(self):
        return self._sessions_uri

    def _set_active_session_uri(self, location):
        if location:
            parsed = urlparse(location)
            self._active_session_uri = parsed.path
        else:
            self._active_session_uri = None

    @property
    def active_session_uri(self):
        return self._active_session_uri

    def _set_active_session_key(self, key):
        self._active_session_key = key

    @property
    def active_session_key(self):
        return self._active_session_key

    def set_server_sent_event_uri(self, uri):
        self._sse_uri = uri

    @property
    def server_sent_event_uri(self):
        return self._sse_uri

    def set_event_dest_uri(self, uri):
        self._event_dest_uri = uri

    @property
    def event_dest_uri(self):
        return self._event_dest_uri

    def set_mgr_net_proto_uri(self, uri):
        self._mgr_net_proto_uri = uri

    @property
    def mgr_net_proto_uri(self):
        return self._mgr_net_proto_uri

    def add_ssdp_services(self, search_target, services):
        self._ssdp_services[search_target] = services

    def get_ssdp_services(self, search_target):
        return self._ssdp_services.get(search_target, {})

    def get_ssdp_service(self, search_target, uuid):
        services = self._ssdp_services.get(search_target, {})
        return services.get(uuid)

    def set_ssdp_enabled(self, enabled):
        self._ssdp_enabled = enabled

    @property
    def ssdp_enabled(self):
        return self._ssdp_enabled

    def set_avoid_http_redirect(self, val: bool):
        self._avoid_http_redirect = val

    @property
    def avoid_http_redirect(self):
        return self._avoid_http_redirect

    def set_nav_prop_uri(self, prop, uri):
        if prop == 'Systems':
            self._systems_uri = uri
        elif prop == 'Managers':
            self._managers_uri = uri
        elif prop == 'Chassis':
            self._chassis_uri = uri
        elif prop == 'AccountService':
            self._account_service_uri = uri
        elif prop == 'Accounts':
            self._accounts_uri = uri
        elif prop == 'Roles':
            self._roles_uri = uri
        elif prop == 'EventService':
            self._event_service_uri = uri
        elif prop == 'CertificateService':
            self._cert_service_uri = uri
        elif prop == 'PrivilegeMap':
            self._priv_registry = uri
        elif prop == 'Subscriptions':
            self._subscriptions_uri = uri
        else:
            logging.error('Internal error: set_nav_prop_uri() called with '
                          'unrecognized navigation property "%s"' % prop)

    @property
    def systems_uri(self):
        return self._systems_uri

    @property
    def managers_uri(self):
        return self._managers_uri

    @property
    def chassis_uri(self):
        return self._chassis_uri

    @property
    def account_service_uri(self):
        return self._account_service_uri

    @property
    def accounts_uri(self):
        return self._accounts_uri

    @property
    def roles_uri(self):
        return self._roles_uri

    @property
    def event_service_uri(self):
        return self._event_service_uri

    @property
    def privilege_registry_uri(self):
        return self._priv_registry

    @property
    def certificate_service_uri(self):
        return self._cert_service_uri

    @property
    def subscriptions_uri(self):
        return self._subscriptions_uri

    def add_user(self, data):
        if 'UserName' in data:
            self._users[data['UserName']] = data

    def get_users(self):
        return self._users.copy()

    def get_user(self, user):
        return self._users.get(user)

    def get_user_role(self, user):
        return self._users.get(user, {}).get('RoleId')

    def get_user_privs(self, user):
        role = self.get_user_role(user)
        if role:
            return self.get_role_privs(role)

    def get_user_oem_privs(self, user):
        role = self.get_user_role(user)
        if role:
            return self.get_role_oem_privs(role)

    def add_role(self, data):
        if 'Id' in data:
            self._roles[data['Id']] = data
        elif 'RoleId' in data:
            self._roles[data['RoleId']] = data

    def get_roles(self):
        return self._roles.copy()

    def get_role(self, role):
        return self._roles.get(role)

    def get_role_privs(self, role):
        return self._roles.get(role, {}).get('AssignedPrivileges')

    def get_role_oem_privs(self, role):
        return self._roles.get(role, {}).get('OemPrivileges')

    def set_supported_query_params(self, params):
        self._supported_query_params = params

    @property
    def supported_query_params(self):
        return self._supported_query_params

    def add_response(self, uri, response, resource_type=None,
                     request_type=RequestType.NORMAL):
        if request_type not in self._responses:
            self._responses[request_type] = {}
        method = response.request.method
        if method not in self._responses[request_type]:
            self._responses[request_type][method] = {}
        self._responses[request_type][method][uri] = response
        if resource_type:
            if request_type not in self._typed_responses:
                self._typed_responses[request_type] = {}
            if resource_type not in self._typed_responses[request_type]:
                self._typed_responses[request_type][resource_type] = {}
            if method not in self._typed_responses[request_type][
                    resource_type]:
                self._typed_responses[request_type][resource_type][method] = {}
            self._typed_responses[request_type][resource_type][method][uri] = (
                response)
        logging.debug('response status = %s, method = %s, uri = %s, '
                      'resource_type = %s, request_type = %s' % (
                       response.status_code, method, uri, resource_type,
                       request_type))

    def get_all_responses(self, resource_type=None,
                          request_type=RequestType.NORMAL):
        res_dict = self._responses.get(request_type, {})
        if resource_type:
            res_dict = self._typed_responses.get(request_type, {}).get(
                resource_type, {})
        for method in res_dict.keys():
            for uri, response in res_dict[method].items():
                yield uri, response

    def get_responses_by_method(self, method, resource_type=None,
                                request_type=RequestType.NORMAL):
        if resource_type:
            return self._typed_responses.get(request_type, {}).get(
                resource_type, {}).get(method, {})
        else:
            return self._responses.get(request_type, {}).get(method, {})

    def get_response(self, method, uri, request_type=RequestType.NORMAL):
        return self._responses.get(request_type, {}).get(method, {}).get(uri)

    def get_all_uris(self, resource_type=None,
                     request_type=RequestType.NORMAL):
        res_dict = self._responses.get(request_type, {})
        if resource_type:
            res_dict = self._typed_responses.get(request_type, {}).get(
                resource_type, {})
        return {u for m in res_dict.keys() for u, _ in res_dict[m].items()}

    def add_cert(self, coll_uri, cert_uri):
        if coll_uri in self._cert_coll:
            if cert_uri not in self._cert_coll[coll_uri]:
                self._cert_coll[coll_uri].append(cert_uri)
        else:
            self._cert_coll[coll_uri] = [cert_uri]

    def get_certs(self):
        return self._cert_coll

    @property
    def results(self):
        return self._results

    def log(self, result, method, status, uri, assertion, msg):
        entry = {
            'result': result,
            'method': method,
            'status': status,
            'uri': uri,
            'assertion': assertion,
            'msg': msg
        }
        if assertion in self._results:
            self._results[assertion].append(entry)
        else:
            self._results[assertion] = [entry]
        self._summary[result] += 1

    def add_priv_info(self, priv_info):
        if priv_info:
            self._priv_info.add(priv_info)

    @property
    def priv_info(self):
        return self._priv_info

    def summary_count(self, result):
        return self._summary[result]

    def _get_sessions_uri(self, headers):
        """
        Get the Sessions URI by following the the links from the ServiceRoot

        :param headers: HTTP headers to pass to the GET requests
        :return: the Sessions URI
        """
        r = requests.get(self.rhost + '/redfish/v1/', headers=headers,
                         verify=self.verify)
        if r.status_code == requests.codes.OK:
            data = r.json()
            if 'Links' in data and 'Sessions' in data['Links']:
                return data['Links']['Sessions']['@odata.id']
            elif 'SessionService' in data:
                uri = data['SessionService']['@odata.id']
                r = requests.get(self.rhost + uri, headers=headers,
                                 auth=(self.username, self.password),
                                 verify=self.verify)
                if r.status_code == requests.codes.OK:
                    data = r.json()
                    if 'Sessions' in data:
                        return data['Sessions']['@odata.id']
        return '/redfish/v1/SessionService/Sessions'

    def login(self):
        """
        Login to the Redfish service and establish a session

        :return: the `requests.Session` object
        """
        payload = {
            'UserName': self.username,
            'Password': self.password
        }
        headers = {
            'OData-Version': '4.0'
        }
        sessions_uri = self._get_sessions_uri(headers)
        self.set_sessions_uri(sessions_uri)
        session = requests.Session()
        response = requests.post(self.rhost + sessions_uri, json=payload,
                                 headers=headers, verify=self.verify)
        if response.ok:
            # Redfish Session created; use it
            location = response.headers.get('Location')
            self._set_active_session_uri(location)
            token = response.headers.get('X-Auth-Token')
            if token:
                self._set_active_session_key(token)
                session.headers.update({'X-Auth-Token': token})
                self.add_priv_info(token)
            else:
                # X-Auth-Token missing; fall back to basic auth
                session.auth = (self.username, self.password)
                logging.warning('Redfish session created but no X-Auth-Token '
                                'header returned')
        else:
            # Redfish Session creation failed; fall back to basic auth
            session.auth = (self.username, self.password)
            logging.warning('Creating Redfish session failed with status %s; '
                            'using Basic authentication' %
                            response.status_code)
        session.headers.update({'OData-Version': '4.0'})
        session.headers.update({'Accept-Encoding': 'identity'})
        # session.headers.update({'Accept': 'application/json'})
        session.verify = self.verify
        self._set_session(session)
        return session

    def logout(self):
        if self.active_session_uri:
            response = self.session.delete(
                self.rhost + self.active_session_uri)
            if response.ok:
                self._set_session(None)
                self._set_active_session_uri(None)
                self._set_active_session_key(None)
            else:
                logging.error('Deleting session %s returned status %s' %
                              (self.active_session_uri, response.status_code))
