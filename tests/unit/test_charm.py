# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, patch

import pytest
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import RouterOperatorCharm


class TestCharm(unittest.TestCase):
    @patch("lightkube.core.client.GenericSyncClient")
    def setUp(self, patch_k8s_client):
        self.harness = testing.Harness(RouterOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_cant_connect_to_workload_when_config_changed_then_status_is_waiting(self):
        self.harness.set_can_connect(container="router", val=False)

        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for workload container to be ready"),
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_multus_not_ready_when_config_changed_then_status_is_waiting(
        self, patch_is_ready
    ):
        self.harness.set_can_connect(container="router", val=True)
        patch_is_ready.return_value = False

        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for Multus to be ready"),
        )

    @patch("ops.model.Container.exec")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_multus_is_ready_when_config_changed_then_ip_forwarding_is_set(
        self, patch_is_ready, patch_exec
    ):
        patch_exec_return_value = Mock()
        patch_exec_return_value.wait_output.return_value = "net.ipv4.ip_forward = 1", "stderr"
        patch_exec.return_value = patch_exec_return_value
        self.harness.set_can_connect(container="router", val=True)
        patch_is_ready.return_value = True

        self.harness.update_config()

        patch_exec.assert_any_call(command=["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=30)

    @patch("ops.model.Container.exec")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_multus_is_ready_when_config_changed_then_iptables_rule_is_set(
        self, patch_is_ready, patch_exec
    ):
        patch_exec_return_value = Mock()
        patch_exec_return_value.wait_output.return_value = "net.ipv4.ip_forward = 1", "stderr"
        patch_exec.return_value = patch_exec_return_value
        self.harness.set_can_connect(container="router", val=True)
        patch_is_ready.return_value = True

        self.harness.update_config()

        patch_exec.assert_any_call(
            command=[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            ],
            timeout=30,
        )

    @patch("ops.model.Container.exec")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_error_when_setting_ip_forwarding_when_config_changed_then_runtime_error_is_raised(  # noqa: E501
        self, patch_is_ready, patch_exec
    ):
        stderr = "whatever error content"
        patch_exec_return_value = Mock()
        patch_exec_return_value.wait_output.return_value = "", stderr
        patch_exec.return_value = patch_exec_return_value
        self.harness.set_can_connect(container="router", val=True)
        patch_is_ready.return_value = True

        with pytest.raises(RuntimeError) as e:
            self.harness.update_config()

        self.assertEqual(
            str(e.value), f"Could not set IP forwarding in workload container: {stderr}"
        )

    @patch("ops.model.Container.exec")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_ip_forwarding_set_correctly_when_config_changed_then_status_is_active(
        self, patch_is_ready, patch_exec
    ):
        patch_exec_return_value = Mock()
        patch_exec_return_value.wait_output.return_value = "net.ipv4.ip_forward = 1", "stderr"
        patch_exec.return_value = patch_exec_return_value
        self.harness.set_can_connect(container="router", val=True)
        patch_is_ready.return_value = True

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_empty_ip_when_config_changed_then_status_is_blocked(self, patch_is_ready):
        patch_is_ready.return_value = True
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(key_values={"core-gateway-ip": ""})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['core-gateway-ip']"),
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_invalid_ip_when_config_changed_then_status_is_blocked(self, patch_is_ready):
        patch_is_ready.return_value = True
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(key_values={"core-gateway-ip": "a.b.c.d"})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['core-gateway-ip']"),
        )
