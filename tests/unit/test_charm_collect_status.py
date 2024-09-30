# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
import scenario
from ops import ActiveStatus, BlockedStatus, WaitingStatus

from tests.unit.fixtures import RouterUnitTestFixtures


class TestCharmCollectUnitStatus(RouterUnitTestFixtures):
    def test_given_multus_not_enabled_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_k8s_multus.multus_is_available.return_value = False
        container = scenario.Container(name="router", can_connect=True)
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Multus is not installed or enabled")

    @pytest.mark.parametrize(
        "config_param,value",
        [
            pytest.param("core-interface-mtu-size", 0, id="core-interface-mtu-size"),
            pytest.param("core-gateway-ip", "", id="core-gateway-ip"),
            pytest.param("access-interface-mtu-size", 0, id="access-interface-mtu-size"),
            pytest.param("access-gateway-ip", "", id="access-gateway-ip"),
            pytest.param("ran-interface-mtu-size", 0, id="ran-interface-mtu-size"),
            pytest.param("ran-gateway-ip", "", id="ran-gateway-ip"),
            pytest.param("ue-subnet", "", id="ue-subnet"),
            pytest.param("upf-core-ip", "", id="upf-core-ip"),
        ],
    )
    def test_given_invalid_config_when_collect_unit_status_then_status_is_blocked(
        self, config_param, value
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        container = scenario.Container(name="router", can_connect=True)

        state_in = scenario.State(
            leader=True, containers=[container], config={config_param: value}
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            f"The following configurations are not valid: ['{config_param}']"
        )

    def test_given_cant_connect_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        container = scenario.Container(name="router", can_connect=False)
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for workload container to be ready")

    def test_given_multus_not_ready_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = False
        container = scenario.Container(name="router", can_connect=True)
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Multus to be ready")

    def test_given_prerequisites_met_when_collect_unit_status_then_status_is_active(
        self,
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = True
        container = scenario.Container(name="router", can_connect=True)
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus()
