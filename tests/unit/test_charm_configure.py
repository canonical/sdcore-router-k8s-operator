# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
import scenario

from tests.unit.fixtures import RouterUnitTestFixtures


class TestCharmConfigure(RouterUnitTestFixtures):
    def test_given_prerequisites_met_when_configure_then_ip_forwarding_and_iptables_is_set(
        self, caplog
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = True
        ip_forward_call = ("sysctl", "-w", "net.ipv4.ip_forward=1")
        iptables_call = (
            "iptables-legacy",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
        )
        container = scenario.Container(
            name="router",
            can_connect=True,
            exec_mock={
                ip_forward_call: scenario.ExecOutput(
                    return_code=0, stdout="net.ipv4.ip_forward = 1"
                ),
                iptables_call: scenario.ExecOutput(return_code=0, stdout=""),
            },
        )
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        self.ctx.run(container.pebble_ready_event, state_in)

        # When scenario 7 is out, we should assert that the mock exec was called
        # instead of validating log content
        # Reference: https://github.com/canonical/ops-scenario/issues/180
        assert "Successfully set IP forwarding" in caplog.text
        assert "Successfully set ip tables" in caplog.text

    def test_error_when_setting_up_ip_forwarding_when_configure_then_error_raised(self, caplog):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = True
        ip_forward_call = ("sysctl", "-w", "net.ipv4.ip_forward=1")
        iptables_call = (
            "iptables-legacy",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
        )
        container = scenario.Container(
            name="router",
            can_connect=True,
            exec_mock={
                ip_forward_call: scenario.ExecOutput(
                    return_code=0, stdout="", stderr="whatever error message"
                ),
                iptables_call: scenario.ExecOutput(return_code=0, stdout=""),
            },
        )
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )

        with pytest.raises(Exception) as e:
            self.ctx.run(container.pebble_ready_event, state_in)

        assert "Could not set IP forwarding in workload container: whatever error message" in str(
            e.value
        )
