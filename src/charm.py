#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's router for K8s."""

import ipaddress
import json
import logging
from typing import Any, Dict, Optional

from charms.kubernetes_charm_libraries.v0.multus import (  # type: ignore[import]
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from lightkube.models.meta_v1 import ObjectMeta
from ops import EventSource
from ops.charm import CharmBase, CharmEvents, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

logger = logging.getLogger(__name__)

CORE_GW_NAD_NAME = "core-gw"
ACCESS_GW_NAD_NAME = "access-gw"
RAN_GW_NAD_NAME = "ran-gw"
CORE_INTERFACE_NAME = "core"
ACCESS_INTERFACE_NAME = "access"
RAN_INTERFACE_NAME = "ran"
ACCESS_INTERFACE_BRIDGE_NAME = "access-br"
CORE_INTERFACE_BRIDGE_NAME = "core-br"
RAN_INTERFACE_BRIDGE_NAME = "ran-br"
CNI_VERSION = "0.3.1"


class NadConfigChangedEvent(EventBase):
    """Event triggered when an existing network attachment definition is changed."""


class KubernetesMultusCharmEvents(CharmEvents):
    """Kubernetes Multus charm events."""

    nad_config_changed = EventSource(NadConfigChangedEvent)


class RouterOperatorCharm(CharmBase):
    """Charm the service."""

    on = KubernetesMultusCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self._container_name = self._service_name = "router"
        self._container = self.unit.get_container(self._container_name)
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            container_name=self._container_name,
            cap_net_admin=True,
            privileged=True,
            network_annotations=[
                NetworkAnnotation(
                    name=CORE_GW_NAD_NAME,
                    interface=CORE_INTERFACE_NAME,
                ),
                NetworkAnnotation(
                    name=RAN_GW_NAD_NAME,
                    interface=RAN_INTERFACE_NAME,
                ),
                NetworkAnnotation(
                    name=ACCESS_GW_NAD_NAME,
                    interface=ACCESS_INTERFACE_NAME,
                ),
            ],
            network_attachment_definitions_func=self._network_attachment_definitions_from_config,
            refresh_event=self.on.nad_config_changed,
        )
        self.framework.observe(self.on.router_pebble_ready, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)

    def _configure(self, event: EventBase) -> None:
        """Config changed event."""
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        self.on.nad_config_changed.emit()
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for workload container to be ready")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._set_ip_forwarding()
        self._set_ip_tables()
        self.unit.status = ActiveStatus()

    def _get_invalid_configs(self) -> list[str]:
        invalid_configs = []
        if not self._core_gateway_ip_is_valid():
            invalid_configs.append("core-gateway-ip")
        if not self._access_gateway_ip_is_valid():
            invalid_configs.append("access-gateway-ip")
        if not self._ran_gateway_ip_is_valid():
            invalid_configs.append("ran-gateway-ip")
        if not self._ue_subnet_is_valid():
            invalid_configs.append("ue-subnet")
        if not self._upf_core_ip_is_valid():
            invalid_configs.append("upf-core-ip")
        if not self._access_interface_mtu_size_is_valid():
            invalid_configs.append("access-interface-mtu-size")
        if not self._core_interface_mtu_size_is_valid():
            invalid_configs.append("core-interface-mtu-size")
        if not self._ran_interface_mtu_size_is_valid():
            invalid_configs.append("ran-interface-mtu-size")
        return invalid_configs

    def _exec_command_in_workload(self, command: str) -> tuple:
        """Executes command in workload container.

        Args:
            command: Command to execute
        """
        process = self._container.exec(
            command=command.split(),
            timeout=30,
        )
        return process.wait_output()

    def _network_attachment_definitions_from_config(self) -> list[NetworkAttachmentDefinition]:
        """Returns list of Multus NetworkAttachmentDefinitions to be created based on config.

        Returns:
            network_attachment_definitions: list[NetworkAttachmentDefinition]

        """
        core_nad_config = self._get_core_nad_config()
        if (core_interface := self._get_core_interface_config()) is not None:
            core_nad_config.update({"type": "macvlan", "master": core_interface})
        else:
            core_nad_config.update({"type": "bridge", "bridge": CORE_INTERFACE_BRIDGE_NAME})

        ran_nad_config = self._get_ran_nad_config()
        if (ran_interface := self._get_ran_interface_config()) is not None:
            ran_nad_config.update({"type": "macvlan", "master": ran_interface})
        else:
            ran_nad_config.update({"type": "bridge", "bridge": RAN_INTERFACE_BRIDGE_NAME})

        access_nad_config = self._get_access_nad_config()
        if (access_interface := self._get_access_interface_config()) is not None:
            access_nad_config.update({"type": "macvlan", "master": access_interface})
        else:
            access_nad_config.update({"type": "bridge", "bridge": ACCESS_INTERFACE_BRIDGE_NAME})
        return [
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=CORE_GW_NAD_NAME),
                spec={"config": json.dumps(core_nad_config)},
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=RAN_GW_NAD_NAME),
                spec={"config": json.dumps(ran_nad_config)},
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=ACCESS_GW_NAD_NAME),
                spec={"config": json.dumps(access_nad_config)},
            ),
        ]

    def _get_core_nad_config(self) -> Dict[Any, Any]:
        """Get core interface NAD config.

        Returns:
            config (dict): Core interface NAD config
        """
        config = {
            "cniVersion": CNI_VERSION,
            "ipam": {
                "type": "static",
                "routes": [
                    {
                        "dst": self._get_ue_subnet_config(),
                        "gw": self._get_upf_core_ip_config(),
                    }
                ],
                "addresses": [
                    {
                        "address": self._get_core_gateway_ip_config(),
                    }
                ],
            },
            "capabilities": {"mac": True},
        }
        if core_mtu := self._get_core_interface_mtu_config():
            config.update({"mtu": core_mtu})
        return config

    def _get_ran_nad_config(self) -> Dict[Any, Any]:
        """Get RAN interface NAD config.

        Returns:
            config (dict): RAN interface NAD config
        """
        config = {
            "cniVersion": CNI_VERSION,
            "ipam": {
                "type": "static",
                "addresses": [
                    {
                        "address": self._get_ran_gateway_ip_config(),
                    }
                ],
            },
            "capabilities": {"mac": True},
        }
        if ran_mtu := self._get_ran_interface_mtu_config():
            config.update({"mtu": ran_mtu})
        return config

    def _get_access_nad_config(self) -> Dict[Any, Any]:
        """Get access interface NAD config.

        Returns:
            config (dict): Access interface NAD config
        """
        config = {
            "cniVersion": CNI_VERSION,
            "ipam": {
                "type": "static",
                "addresses": [
                    {
                        "address": self._get_access_gateway_ip_config(),
                    }
                ],
            },
            "capabilities": {"mac": True},
        }
        if access_mtu := self._get_access_interface_mtu_config():
            config.update({"mtu": access_mtu})
        return config

    def _set_ip_tables(self) -> None:
        """Configures firewall for IP masquerading.

        Masks requests with the IP address of the firewall's eth0 interface.
        """
        self._exec_command_in_workload(
            command="iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
        )
        logger.info("Successfully set ip tables")

    def _set_ip_forwarding(self) -> None:
        """Sets IP forwarding in workload container."""
        stdout, stderr = self._exec_command_in_workload(command="sysctl -w net.ipv4.ip_forward=1")
        if "net.ipv4.ip_forward = 1" not in stdout:
            raise RuntimeError(f"Could not set IP forwarding in workload container: {stderr}")
        logger.info("Successfully set IP forwarding")

    def _core_gateway_ip_is_valid(self) -> bool:
        ip = self._get_core_gateway_ip_config()
        if not ip:
            return False
        return ip_in_cidr_format_is_valid(ip)

    def _access_gateway_ip_is_valid(self) -> bool:
        ip = self._get_access_gateway_ip_config()
        if not ip:
            return False
        return ip_in_cidr_format_is_valid(ip)

    def _ran_gateway_ip_is_valid(self) -> bool:
        ip = self._get_ran_gateway_ip_config()
        if not ip:
            return False
        return ip_in_cidr_format_is_valid(ip)

    def _ue_subnet_is_valid(self) -> bool:
        ip = self._get_ue_subnet_config()
        if not ip:
            return False
        return ip_in_cidr_format_is_valid(ip)

    def _upf_core_ip_is_valid(self) -> bool:
        ip = self._get_upf_core_ip_config()
        if not ip:
            return False
        return ip_is_valid(ip)

    def _core_interface_mtu_size_is_valid(self) -> bool:
        """Checks whether the core interface MTU size is valid.

        Returns:
            bool: Whether core interface MTU size is valid
        """
        if (core_mtu := self._get_core_interface_mtu_config()) is None:
            return True
        try:
            return 1200 <= int(core_mtu) <= 65535
        except ValueError:
            return False

    def _access_interface_mtu_size_is_valid(self) -> bool:
        """Checks whether the access interface MTU size is valid.

        Returns:
            bool: Whether access interface MTU size is valid
        """
        if (access_mtu := self._get_access_interface_mtu_config()) is None:
            return True
        try:
            return 1200 <= int(access_mtu) <= 65535
        except ValueError:
            return False

    def _ran_interface_mtu_size_is_valid(self) -> bool:
        """Checks whether the RAN interface MTU size is valid.

        Returns:
            bool: Whether RAN interface MTU size is valid
        """
        if (ran_mtu := self._get_ran_interface_mtu_config()) is None:
            return True
        try:
            return 1200 <= int(ran_mtu) <= 65535
        except ValueError:
            return False

    def _get_core_interface_config(self) -> Optional[str]:
        return self.model.config.get("core-interface")

    def _get_core_interface_mtu_config(self) -> Optional[str]:
        """Get Core interface MTU size.

        Returns:
            mtu_size (str/None): If MTU size is not configured return None
                                If it is set, returns the configured value
        """
        return self.model.config.get("core-interface-mtu-size")

    def _get_core_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-gateway-ip")

    def _get_access_interface_config(self) -> Optional[str]:
        return self.model.config.get("access-interface")

    def _get_access_interface_mtu_config(self) -> Optional[str]:
        """Get access interface MTU size.

        Returns:
            mtu_size (str/None): If MTU size is not configured return None
                                If it is set, returns the configured value
        """
        return self.model.config.get("access-interface-mtu-size")

    def _get_access_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-gateway-ip")

    def _get_ran_interface_config(self) -> Optional[str]:
        return self.model.config.get("ran-interface")

    def _get_ran_interface_mtu_config(self) -> Optional[str]:
        """Get RAN interface MTU size.

        Returns:
            mtu_size (str/None): If MTU size is not configured return None
                                If it is set, returns the configured value
        """
        return self.model.config.get("ran-interface-mtu-size")

    def _get_ran_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("ran-gateway-ip")

    def _get_ue_subnet_config(self) -> Optional[str]:
        return self.model.config.get("ue-subnet")

    def _get_upf_core_ip_config(self) -> Optional[str]:
        return self.model.config.get("upf-core-ip")


def ip_is_valid(ip_address: str) -> bool:
    """Check whether given IP config is valid.

    Args:
        ip_address (str): IP address

    Returns:
        bool: True if given IP address is valid
    """
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return True
    except ValueError:
        return False


def ip_in_cidr_format_is_valid(ip_address: str) -> bool:
    """Check whether given IP config is in CIDR format and valid.

    Args:
        ip_address (str): IP address in CIDR format

    Returns:
        bool: True if given IP address is valid
    """
    if "/" not in ip_address:
        logger.error("The IP address: %s is expected in CIDR format.", ip_address)
        return False
    return ip_is_valid(ip_address)


if __name__ == "__main__":  # pragma: no cover
    main(RouterOperatorCharm)
