# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from unittest.mock import patch

import pytest
from charm import RouterOperatorCharm
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from lib.charms.kubernetes_charm_libraries.v0.multus import NetworkAttachmentDefinition

ACCESS_GATEWAY_IP = "192.168.252.1"
CORE_GATEWAY_IP = "192.168.250.1"
RAN_GATEWAY_IP = "192.168.251.1"
UE_SUBNET = "172.250.0.0"
INVALID_STRING_IP = "a.b.c.d"
VALID_MASK_24 = 24
INVALID_MASK_TOO_LOW = -1
VALID_MASK_LOWER_EDGE = 0
VALID_MASK_LOW = 1
VALID_MASK_HIGH = 31
VALID_MASK_UPPER_EDGE = 32
INVALID_MASK_TOO_HIGH = 33
MULTUS_LIBRARY_PATH = "charms.kubernetes_charm_libraries.v0.multus"
TOO_BIG_MTU_SIZE = 65536  # Out of range
TOO_SMALL_MTU_SIZE = 1199  # Out of range
ZERO_MTU_SIZE = 0  # Out of range
VALID_MTU_SIZE_1 = 65535  # Upper edge value
VALID_MTU_SIZE_2 = 1200  # Lower edge value


def update_nad_labels(nads: list[NetworkAttachmentDefinition], app_name: str) -> None:
    """Set NetworkAttachmentDefinition metadata labels.

    Args:
        nads: list of NetworkAttachmentDefinition
        app_name: application name
    """
    for nad in nads:
        assert nad.metadata
        nad.metadata.labels = {"app.juju.is/created-by": app_name}


class TestCharm:
    patcher_k8s_client = patch("lightkube.core.client.GenericSyncClient")
    patcher_list_na_definitions = patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")  # noqa: E501
    patcher_delete_pod = patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    patcher_multus_is_ready = patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    patcher_multus_is_available = patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.multus_is_available")  # noqa: E501

    @pytest.fixture()
    def setup(self):
        TestCharm.patcher_k8s_client.start()
        self.mock_list_na_definitions = TestCharm.patcher_list_na_definitions.start()
        self.mock_delete_pod = TestCharm.patcher_delete_pod.start()
        self.mock_multus_is_ready = TestCharm.patcher_multus_is_ready.start()
        self.mock_multus_is_available = TestCharm.patcher_multus_is_available.start()

    @staticmethod
    def teardown():
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = testing.Harness(RouterOperatorCharm)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    def test_given_cant_connect_to_workload_when_config_changed_then_status_is_waiting(self):
        self.harness.set_can_connect(container="router", val=False)

        self.harness.update_config()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for workload container to be ready"
        )

    def test_given_multus_not_ready_when_config_changed_then_status_is_waiting(self):
        self.harness.set_can_connect(container="router", val=True)
        self.mock_multus_is_ready.return_value = False

        self.harness.update_config()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for Multus to be ready")

    def test_given_multus_is_ready_when_config_changed_then_ip_forwarding_is_set(self):
        sysctl_called = False
        timeout = 0
        sysctl_cmd = ["sysctl", "-w", "net.ipv4.ip_forward=1"]

        def sysctl_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal sysctl_called
            nonlocal timeout
            sysctl_called = True
            timeout = args.timeout
            return testing.ExecResult(stdout="net.ipv4.ip_forward = 1")

        self.harness.handle_exec("router", sysctl_cmd, handler=sysctl_handler)
        self.harness.handle_exec("router", [], result=0)

        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config()

        assert sysctl_called is True
        assert timeout == 30

    def test_given_multus_is_ready_when_config_changed_then_iptables_rule_is_set(self):
        iptables_called = False
        timeout = 0
        iptables_cmd = [
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

        def iptables_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal iptables_called
            nonlocal timeout
            iptables_called = True
            timeout = args.timeout
            return testing.ExecResult()

        self.harness.handle_exec("router", iptables_cmd, handler=iptables_handler)
        self.harness.handle_exec("router", ["sysctl"], result="net.ipv4.ip_forward = 1")
        self.harness.handle_exec("router", [], result=0)

        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config()

        assert iptables_called is True
        assert timeout == 30

    def test_given_error_when_setting_ip_forwarding_when_config_changed_then_runtime_error_is_raised(self):  # noqa: E501
        stderr = "whatever error content"
        sysctl_cmd = ["sysctl", "-w", "net.ipv4.ip_forward=1"]

        def sysctl_handler(_: testing.ExecArgs) -> testing.ExecResult:
            return testing.ExecResult(stderr=stderr)

        self.harness.handle_exec("router", sysctl_cmd, handler=sysctl_handler)
        self.harness.handle_exec("router", [], result=0)
        self.harness.set_can_connect(container="router", val=True)

        with pytest.raises(RuntimeError) as e:
            self.harness.update_config()

        assert str(e.value) == f"Could not set IP forwarding in workload container: {stderr}"

    def test_given_ip_forwarding_set_correctly_when_config_changed_then_status_is_active(self):
        self.harness.handle_exec("router", ["sysctl"], result="net.ipv4.ip_forward = 1")
        self.harness.handle_exec("router", [], result=0)
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_empty_ip_when_config_changed_then_status_is_blocked(self):
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(key_values={"core-gateway-ip": ""})
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "The following configurations are not valid: ['core-gateway-ip']"
        )

    def test_given_invalid_non_cidr_ip_when_config_changed_then_status_is_blocked(self):
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(
            key_values={
                "access-gateway-ip": ACCESS_GATEWAY_IP,
                "core-gateway-ip": CORE_GATEWAY_IP,
                "ran-gateway-ip": RAN_GATEWAY_IP,
                "ue-subnet": UE_SUBNET,
                "upf-core-ip": "192.168.250.3",
            }
        )
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
                "The following configurations are not valid: "
                "['core-gateway-ip', 'access-gateway-ip', 'ran-gateway-ip', 'ue-subnet']"
            )

    def test_given_ip_in_cidr_format_with_too_big_mask_when_config_changed_then_status_is_blocked(self):  # noqa: E501
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(
            key_values={
                "access-gateway-ip": f"{ACCESS_GATEWAY_IP}/{INVALID_MASK_TOO_HIGH}",
                "core-gateway-ip": f"{CORE_GATEWAY_IP}/{VALID_MASK_UPPER_EDGE}",
                "ran-gateway-ip": f"{RAN_GATEWAY_IP}/{VALID_MASK_HIGH}",
                "ue-subnet": f"{UE_SUBNET}/{VALID_MASK_HIGH}",
            }
        )
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "The following configurations are not valid: ['access-gateway-ip']"
        )

    def test_given_gateway_ip_in_cidr_format_with_too_small_mask_when_config_changed_then_status_is_blocked(self):  # noqa: E501
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(
            key_values={
                "access-gateway-ip": f"{ACCESS_GATEWAY_IP}/{VALID_MASK_LOW}",
                "core-gateway-ip": f"{CORE_GATEWAY_IP}/{INVALID_MASK_TOO_LOW}",
                "ran-gateway-ip": f"{RAN_GATEWAY_IP}/{VALID_MASK_LOWER_EDGE}",
                "ue-subnet": f"{UE_SUBNET}/{INVALID_MASK_TOO_LOW}",
            }
        )
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "The following configurations are not valid: ['core-gateway-ip', 'ue-subnet']"
        )

    def test_given_string_gateway_ip_when_config_changed_then_status_is_blocked(self):
        self.harness.set_can_connect(container="router", val=True)

        self.harness.update_config(
            key_values={
                "access-gateway-ip": INVALID_STRING_IP,
                "core-gateway-ip": INVALID_STRING_IP,
                "ran-gateway-ip": INVALID_STRING_IP,
            }
        )
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
                "The following configurations are not valid: "
                "['core-gateway-ip', 'access-gateway-ip', 'ran-gateway-ip']"
            )

    def test_given_multus_disabled_then_enabled_when_update_status_then_status_is_active(self):
        self.mock_multus_is_available.side_effect = [False, False, True, True]
        self.harness.handle_exec("router", ["sysctl"], result="net.ipv4.ip_forward = 1")
        self.harness.handle_exec("router", [], result=0)
        self.harness.set_can_connect(container="router", val=True)
        self.harness.update_config()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Multus is not installed or enabled"
        )

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_specified_in_nad(  # noqa: E501
        self,
    ):
        self.harness.disable_hooks()
        self.harness.update_config(
            key_values={
                "access-gateway-ip": f"{ACCESS_GATEWAY_IP}/{VALID_MASK_24}",
                "core-gateway-ip": f"{CORE_GATEWAY_IP}/{VALID_MASK_24}",
                "ran-gateway-ip": f"{RAN_GATEWAY_IP}/{VALID_MASK_24}",
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "master" not in config
            assert "bridge" == config["type"]
            assert config["bridge"] in ("access-br", "core-br", "ran-br")

    def test_given_default_config_with_interfaces_when_network_attachment_definitions_from_config_is_called_then_interfaces_specified_in_nad(  # noqa: E501
        self,
    ):
        self.harness.disable_hooks()
        self.harness.update_config(
            key_values={
                "access-interface": "access-gw",
                "access-gateway-ip": f"{ACCESS_GATEWAY_IP}/{VALID_MASK_24}",
                "core-interface": "core-gw",
                "core-gateway-ip": f"{CORE_GATEWAY_IP}/{VALID_MASK_24}",
                "ran-interface": "ran-gw",
                "ran-gateway-ip": f"{RAN_GATEWAY_IP}/{VALID_MASK_24}",
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            assert nad.metadata
            config = json.loads(nad.spec["config"])
            assert config["master"] == nad.metadata.name
            assert config["type"] == "macvlan"

    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_mtu_specified_in_nad(self):  # noqa: E501
        self.harness.update_config(
            key_values={
                "access-gateway-ip": ACCESS_GATEWAY_IP,
                "core-gateway-ip": CORE_GATEWAY_IP,
                "ran-gateway-ip": RAN_GATEWAY_IP,
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "master" not in config
            assert "bridge" == config["type"]
            assert config["bridge"] in ("access-br", "core-br", "ran-br")
            assert "mtu" not in config

    def test_given_default_config_when_config_is_updated_with_valid_mtu_sizes_then_mtu_sizes_specified_in_nad(self):  # noqa: E501
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": VALID_MTU_SIZE_1,
                "core-interface-mtu-size": VALID_MTU_SIZE_1,
                "ran-interface-mtu-size": VALID_MTU_SIZE_1,
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "master" not in config
            assert "bridge" == config["type"]
            assert VALID_MTU_SIZE_1 == config["mtu"]
            assert config["bridge"] in ("access-br", "core-br", "ran-br")

    def test_given_default_config_when_config_is_updated_with_too_small_and_big_mtu_sizes_then_status_is_blocked(self):  # noqa: E501
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": TOO_SMALL_MTU_SIZE,
                "core-interface-mtu-size": TOO_BIG_MTU_SIZE,
                "ran-interface-mtu-size": TOO_BIG_MTU_SIZE,
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size', 'ran-interface-mtu-size']"  # noqa: E501, W505
            )

    def test_given_default_config_when_config_is_updated_with_zero_mtu_sizes_then_status_is_blocked(self):  # noqa: E501
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": ZERO_MTU_SIZE,
                "core-interface-mtu-size": ZERO_MTU_SIZE,
                "ran-interface-mtu-size": ZERO_MTU_SIZE,
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size', 'ran-interface-mtu-size']"  # noqa: E501, W505
            )

    def test_given_container_can_connect_when_core_net_mtu_config_changed_to_a_different_valid_value_then_delete_pod_is_called(self):  # noqa: E501
        TestCharm.patcher_multus_is_ready.stop()
        TestCharm.patcher_multus_is_available.stop()
        self.harness.set_can_connect(container="router", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        self.mock_delete_pod.assert_called_once()

    def test_given_container_can_connect_when_core_net_mtu_config_changed_to_different_valid_values_then_delete_pod_is_called_twice(self):  # noqa: E501
        TestCharm.patcher_multus_is_ready.stop()
        TestCharm.patcher_multus_is_available.stop()
        self.harness.set_can_connect(container="router", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        modified_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(modified_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = modified_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        assert self.mock_delete_pod.call_count == 2

    def test_given_container_can_connect_when_core_net_mtu_config_changed_to_same_valid_value_multiple_times_then_delete_pod_is_called_once(self):  # noqa: E501
        TestCharm.patcher_multus_is_ready.stop()
        TestCharm.patcher_multus_is_available.stop()
        self.harness.set_can_connect(container="router", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        self.mock_delete_pod.assert_called_once()
        nads_after_first_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        update_nad_labels(nads_after_first_config_change, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = nads_after_first_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        self.mock_delete_pod.assert_called_once()
        nads_after_second_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        update_nad_labels(nads_after_second_config_change, self.harness.charm.app.name)
        for nad in nads_after_second_config_change:
            assert nad.metadata
            nad.metadata.labels = {"app.juju.is/created-by": self.harness.charm.app.name}
        self.mock_list_na_definitions.return_value = nads_after_second_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        self.mock_delete_pod.assert_called_once()

    def test_given_container_can_connect_when_core_net_mtu_config_changed_to_an_invalid_value_multiple_times_then_delete_pod_is_not_called(self):  # noqa: E501
        TestCharm.patcher_multus_is_ready.stop()
        TestCharm.patcher_multus_is_available.stop()
        self.harness.set_can_connect(container="router", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": TOO_BIG_MTU_SIZE})
        self.mock_delete_pod.assert_not_called()
