# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario

from charm import RouterOperatorCharm


class RouterUnitTestFixtures:
    patcher_k8s_multus = patch(
        "charm.KubernetesMultusCharmLib",
    )

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_k8s_multus = RouterUnitTestFixtures.patcher_k8s_multus.start().return_value
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=RouterOperatorCharm,
        )
