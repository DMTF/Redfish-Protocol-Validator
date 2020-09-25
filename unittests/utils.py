# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import json as json_util
from unittest import mock

import requests

from assertions.constants import RequestType, ResourceType
from assertions.system_under_test import SystemUnderTest


def add_response(sut: SystemUnderTest, uri, method='GET',
                 status_code=requests.codes.OK, json=None, text=None,
                 res_type=None, request_payload=None, encoding=None,
                 request_type=RequestType.NORMAL, headers=None):
    response = mock.MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.ok = True if status_code < 400 else False
    response.url = sut.rhost + uri
    response.encoding = encoding
    request = mock.Mock(spec=requests.Request)
    request.method = method
    if json is not None:
        response.json.return_value = json
        response.headers = {
            'Content-Type': 'application/json',
            'Content-Length': len(json_util.dumps(json))
        }
        response.text = str(json)
    elif text is not None:
        response.text = text
        response.headers = {
            'Content-Type': 'application/xml',
            'Content-Length': len(text)
        }
    else:
        response.text = ''
        response.headers = {}
    if headers is not None:
        response.headers.update(headers)
    request.body = request_payload
    if res_type == ResourceType.MANAGER_ACCOUNT:
        response.headers['ETag'] = '48305216'
    response.request = request
    sut.add_response(uri, response, resource_type=res_type,
                     request_type=request_type)
    return response


def get_result(sut: SystemUnderTest, assertion, method, uri):
    results = sut.results.get(assertion, [])
    for result in reversed(results):
        if result.get('method') == method and result.get('uri') == uri:
            return result
    return None
