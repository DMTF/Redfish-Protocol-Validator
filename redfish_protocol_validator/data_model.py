# Copyright Notice:
# Copyright 2020-2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import requests

from redfish_protocol_validator import utils
from redfish_protocol_validator.constants import Assertion, RequestType, ResourceType, Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

def test_settings_resources(sut):
    """Perform tests from the 'Settings resource' sub-section of the spec."""

    # Find resources that have a high likelihood of containing a settings resource
    responses = sut.get_responses_by_method('GET', resource_type=ResourceType.BIOS)
    if len(responses) == 0:
        # No resources found
        msg = 'No Bios resource found to test assertion'
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION, msg)
        sut.log(Result.NOT_TESTED, '', '', '',
                Assertion.DATA_SETTINGS_RES_DATA_TYPE, msg)
        return

    # Check each resource for a settings resource
    for uri, response in responses.items():
        if response.ok:
            response_data = response.json()
            check_settings_type = False

            # Try to get the settings resource URI
            settings_uri = response_data.get('@Redfish.Settings', {}).get('SettingsObject', {}).get('@odata.id')

            if settings_uri is not None:
                # Settings annotation found; pass
                sut.log(Result.PASS, 'GET', response.status_code, uri,
                        Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION,
                        'Test passed')
                check_settings_type = True
                settings_response = sut.session.get(sut.rhost + settings_uri)
            else:
                # Not found; probe for potential settings resource
                for segment in ['/SD', '/Settings']:
                    settings_uri = uri + segment
                    settings_response = sut.session.get(sut.rhost + settings_uri)
                    if settings_response.ok:
                        check_settings_type = True
                        msg = ('%s does not contain a settings annotation, but '
                               'the settings resource %s is accessible' %
                               (uri, settings_uri))
                        sut.log(Result.FAIL, response.request.method,
                                response.status_code, uri,
                                Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION, msg)
                        break
                if not settings_response.ok:
                    # No responses
                    msg = ('%s does not contain a settings resource' % uri)
                    sut.log(Result.NOT_TESTED, response.request.method,
                            response.status_code, uri,
                            Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION, msg)

            # If there's a settings resource, compare the resource types
            if check_settings_type:
                settings_response_data = settings_response.json()
                if settings_response.ok:
                    # Successful settings resource response; compare @odata.type
                    if settings_response_data.get('@odata.type') != response_data.get('@odata.type'):
                        msg = ('The settings resource contains @odata.type %s, '
                               'but the active resource contains @odata.type '
                               '%s' % (settings_response_data.get('@odata.type'),
                                       response_data.get('@odata.type')))
                        sut.log(Result.FAIL, response.request.method,
                                response.status_code, uri,
                                Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION,
                                msg)
                    else:
                        sut.log(Result.PASS, 'GET', response.status_code, uri,
                                Assertion.DATA_SETTINGS_RES_DATA_TYPE,
                                'Test passed')
                else:
                    # Could not get the settings resource
                    msg = ('%s request to %s failed with status %s;'
                           'extended error %s' %
                           (settings_response.request.method, settings_uri,
                            settings_response.status_code,
                            utils.get_extended_error(settings_response)))
                    sut.log(Result.WARN, response.request.method,
                            response.status_code, uri,
                            Assertion.DATA_SETTINGS_RES_DATA_TYPE, msg)
            else:
                msg = ('%s does not contain a settings resource' % uri)
                sut.log(Result.NOT_TESTED, response.request.method,
                        response.status_code, uri,
                        Assertion.DATA_SETTINGS_RES_DATA_TYPE, msg)
        else:
            msg = ('%s request to %s failed with status %s;'
                   'extended error %s' %
                   (response.request.method, uri, response.status_code,
                   utils.get_extended_error(response)))
            sut.log(Result.WARN, response.request.method,
                    response.status_code, uri,
                    Assertion.DATA_SETTINGS_RES_SETTINGS_ANNOTATION, msg)
            sut.log(Result.WARN, response.request.method,
                    response.status_code, uri,
                    Assertion.DATA_SETTINGS_RES_DATA_TYPE, msg)


def test_data_model(sut: SystemUnderTest):
    """Perform tests from the 'Data model' section of the spec."""
    test_settings_resources(sut)
