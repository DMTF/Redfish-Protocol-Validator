# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
from unittest import TestCase

from assertions.constants import Assertion, ResourceType, Result


class Constants(TestCase):
    def setUp(self):
        super(Constants, self).setUp()

    def test_assertion_repr(self):
        self.assertEqual(repr(Assertion.PROTO_URI_SAFE_CHARS),
                         '<Assertion.PROTO_URI_SAFE_CHARS>')

    def test_resource_type_repr(self):
        self.assertEqual(repr(ResourceType.MANAGER_ACCOUNT),
                         '<ResourceType.MANAGER_ACCOUNT>')

    def test_result_repr(self):
        self.assertEqual(repr(Result.PASS), '<Result.PASS>')


if __name__ == '__main__':
    unittest.main()
