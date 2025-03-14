#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from ops import testing

from tests.unit.fixtures import RouterUnitTestFixtures


class TestCharmRemove(RouterUnitTestFixtures):
    def test_given_unit_is_leader_when_remove_then_k8s_multus_is_removed(self):
        container = testing.Container(
            name="router",
            can_connect=False,
        )
        state_in = testing.State(leader=True, containers=[container])

        self.ctx.run(self.ctx.on.remove(), state_in)

        self.mock_k8s_multus.remove.assert_called_once()
