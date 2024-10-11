# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
from ops import testing

from tests.unit.fixtures import RouterUnitTestFixtures


class TestCharmConfigure(RouterUnitTestFixtures):
    def test_given_prerequisites_met_when_configure_then_ip_forwarding_and_iptables_is_set(
        self,
    ):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = True
        container = testing.Container(
            name="router",
            can_connect=True,
            execs={
                testing.Exec(
                    command_prefix=["iptables-legacy"],
                    return_code=0,
                    stdout="",
                ),
                testing.Exec(
                    command_prefix=["sysctl"],
                    return_code=0,
                    stdout="net.ipv4.ip_forward = 1",
                ),
            },
        )
        state_in = testing.State(
            leader=True,
            containers={container},
        )

        self.ctx.run(self.ctx.on.pebble_ready(container=container), state_in)

        assert self.ctx.exec_history[container.name][0].command == [
            "sysctl",
            "-w",
            "net.ipv4.ip_forward=1",
        ]
        assert self.ctx.exec_history[container.name][1].command == [
            "iptables-legacy",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
        ]

    def test_error_when_setting_up_ip_forwarding_when_configure_then_error_raised(self, caplog):
        self.mock_k8s_multus.multus_is_available.return_value = True
        self.mock_k8s_multus.is_ready.return_value = True
        container = testing.Container(
            name="router",
            can_connect=True,
            execs={
                testing.Exec(
                    command_prefix=["iptables-legacy"],
                    return_code=0,
                    stdout="",
                ),
                testing.Exec(
                    command_prefix=["sysctl"],
                    return_code=0,
                    stdout="",
                    stderr="whatever error message",
                ),
            },
        )
        state_in = testing.State(
            leader=True,
            containers=[container],
        )

        with pytest.raises(Exception) as e:
            self.ctx.run(self.ctx.on.pebble_ready(container=container), state_in)

        assert "Could not set IP forwarding in workload container: whatever error message" in str(
            e.value
        )
