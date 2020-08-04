# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

from assertions.system_under_test import SystemUnderTest


def test_response_headers(sut: SystemUnderTest):
    """Perform tests from the 'Response headers' sub-section of the spec."""


def test_service_responses(sut: SystemUnderTest):
    """Perform tests from the 'Service responses' section of the spec."""
    test_response_headers(sut)
