# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes specific utilities."""

import json
import logging

import httpx
from lightkube import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.core_v1 import Capabilities
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.types import PatchType

logger = logging.getLogger(__name__)

NETWORK_ATTACHMENT_DEFINITION_NAME = "router-net"

NetworkAttachmentDefinition = create_namespaced_resource(
    group="k8s.cni.cncf.io",
    version="v1",
    kind="NetworkAttachmentDefinition",
    plural="network-attachment-definitions",
)


class Kubernetes:
    """Kubernetes main class."""

    def __init__(self, namespace: str):
        """Initializes K8s client."""
        self.client = Client()
        self.namespace = namespace

    def create_network_attachment_definition(self) -> None:
        """Creates network attachment definitions.

        Returns:
            None
        """
        if not self.network_attachment_definition_created(name=NETWORK_ATTACHMENT_DEFINITION_NAME):
            access_interface_config = {
                "cniVersion": "0.3.1",
                "type": "macvlan",
                "ipam": {"type": "static"},
            }
            access_interface_spec = {"config": json.dumps(access_interface_config)}
            network_attachment_definition = NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=NETWORK_ATTACHMENT_DEFINITION_NAME),
                spec=access_interface_spec,
            )
            self.client.create(obj=network_attachment_definition, namespace=self.namespace)
            logger.info(
                f"NetworkAttachmentDefinition {NETWORK_ATTACHMENT_DEFINITION_NAME} created"
            )

    def network_attachment_definition_created(self, name: str) -> bool:
        """Returns whether a NetworkAttachmentDefinition is created."""
        try:
            self.client.get(
                res=NetworkAttachmentDefinition,
                name=name,
                namespace=self.namespace,
            )
            logger.info(f"NetworkAttachmentDefinition {name} already created")
            return True
        except ApiError as e:
            if e.status.reason == "NotFound":
                logger.info(f"NetworkAttachmentDefinition {name} not yet created")
                return False
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.error(
                    "NetworkAttachmentDefinition resource not found. You may need to install Multus CNI."
                )
                raise
            logger.info("Unexpected error while checking NetworkAttachmentDefinition")
            return False
        return False

    def patch_statefulset(self, statefulset_name: str) -> None:
        """Patches a statefulset with multus annotation.

        Args:
            statefulset_name: Statefulset name.

        Returns:
            None
        """
        if self.statefulset_is_patched(statefulset_name=statefulset_name):
            return
        statefulset = self.client.get(
            res=StatefulSet, name=statefulset_name, namespace=self.namespace
        )
        if not hasattr(statefulset, "spec"):
            raise RuntimeError(f"Could not find `spec` in the {statefulset_name} statefulset")

        multus_annotation = [
            {
                "name": NETWORK_ATTACHMENT_DEFINITION_NAME,
                "interface": "core-gw",
                "ips": ["192.168.250.1/24"],
            },
            {
                "name": NETWORK_ATTACHMENT_DEFINITION_NAME,
                "interface": "ran-gw",
                "ips": ["192.168.251.1/24"],
            },
            {
                "name": NETWORK_ATTACHMENT_DEFINITION_NAME,
                "interface": "access-gw",
                "ips": ["192.168.252.1/24"],
            },
        ]

        statefulset.spec.template.metadata.annotations["k8s.v1.cni.cncf.io/networks"] = json.dumps(
            multus_annotation
        )

        statefulset.spec.template.spec.containers[1].securityContext.privileged = True
        statefulset.spec.template.spec.containers[1].securityContext.capabilities = Capabilities(
            add=[
                "NET_ADMIN",
            ]
        )

        self.client.patch(
            res=StatefulSet,
            name=statefulset_name,
            obj=statefulset,
            patch_type=PatchType.MERGE,
            namespace=self.namespace,
        )
        logger.info(f"Multus annotation added to {statefulset_name} Statefulset")

    def statefulset_is_patched(self, statefulset_name: str) -> bool:
        """Returns whether the statefulset has the expected multus annotation.

        Args:
            statefulset_name: Statefulset name.

        """
        statefulset = self.client.get(
            res=StatefulSet, name=statefulset_name, namespace=self.namespace
        )
        if not hasattr(statefulset, "spec"):
            raise RuntimeError(f"Could not find `spec` in the {statefulset_name} statefulset")

        if "k8s.v1.cni.cncf.io/networks" not in statefulset.spec.template.metadata.annotations:
            logger.info("Multus annotation not yet added to statefulset")
            return False

        return True

    def delete_network_attachment_definition(self) -> None:
        """Deletes network attachment definitions.

        Returns:
            None
        """
        if self.network_attachment_definition_created(name=NETWORK_ATTACHMENT_DEFINITION_NAME):
            self.client.delete(
                res=NetworkAttachmentDefinition,
                name=NETWORK_ATTACHMENT_DEFINITION_NAME,
                namespace=self.namespace,
            )
            logger.info(
                f"NetworkAttachmentDefinition {NETWORK_ATTACHMENT_DEFINITION_NAME} deleted"
            )
