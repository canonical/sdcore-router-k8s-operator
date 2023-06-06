#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's router."""

import json
import logging
from typing import Optional

from charms.kubernetes_charm_libraries.v0.multus import (  # type: ignore[import]
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from lightkube.models.meta_v1 import ObjectMeta
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

logger = logging.getLogger(__name__)

CORE_GW_NAD_NAME = "core-gw"
ACCESS_GW_NAD_NAME = "access-gw"
RAN_GW_NAD_NAME = "ran-gw"
CORE_INTERFACE_NAME = "core"
ACCESS_INTERFACE_NAME = "access"
RAN_INTERFACE_NAME = "ran"


class RouterOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self._container_name = self._service_name = "router"
        self._container = self.unit.get_container(self._container_name)
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            containers_requiring_net_admin_capability=[self._container_name],
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
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _network_attachment_definitions_from_config(self) -> list[NetworkAttachmentDefinition]:
        return [
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=CORE_GW_NAD_NAME),
                spec={
                    "config": json.dumps(
                        {
                            "cniVersion": "0.3.1",
                            "type": "macvlan",
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
                    )
                },
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=RAN_GW_NAD_NAME),
                spec={
                    "config": json.dumps(
                        {
                            "cniVersion": "0.3.1",
                            "type": "macvlan",
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
                    )
                },
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=ACCESS_GW_NAD_NAME),
                spec={
                    "config": json.dumps(
                        {
                            "cniVersion": "0.3.1",
                            "type": "macvlan",
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
                    )
                },
            ),
        ]

    def _on_config_changed(self, event: EventBase) -> None:
        """Config changed event."""
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for workload container to be ready")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._set_ip_forwarding()
        self.unit.status = ActiveStatus()

    def _set_ip_forwarding(self) -> None:
        """Sets ip forwarding in workload container."""
        command = "sysctl -w net.ipv4.ip_forward=1"
        process = self._container.exec(
            command=command.split(),
            timeout=30,
        )
        stdout, stderr = process.wait_output()
        if "net.ipv4.ip_forward = 1" not in stdout:
            raise RuntimeError(f"Could not set IP forwarding in workload container: {stderr}")
        logger.info("Successfully set IP forwarding")

    def _get_core_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-gateway-ip")

    def _get_access_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-gateway-ip")

    def _get_ran_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("ran-gateway-ip")

    def _get_ue_subnet_config(self) -> Optional[str]:
        return self.model.config.get("ue-subnet")

    def _get_upf_core_ip_config(self) -> Optional[str]:
        return self.model.config.get("upf-core-ip")


if __name__ == "__main__":  # pragma: no cover
    main(RouterOperatorCharm)
