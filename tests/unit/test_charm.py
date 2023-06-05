# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from ops import testing

from charm import RouterOperatorCharm


class TestCharm(unittest.TestCase):

    def setUp(self):
        self.harness = testing.Harness(RouterOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_when_then(self):
        pass
