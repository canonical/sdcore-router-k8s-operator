#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]
GRAFANA_AGENT_CHARM_NAME = "grafana-agent-k8s"


async def deploy_grafana_agent(ops_test):
    """Deploy the grafana-agent charm."""
    await ops_test.model.deploy(
        GRAFANA_AGENT_CHARM_NAME,
        application_name=GRAFANA_AGENT_CHARM_NAME,
        channel="stable",
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    resources = {
        "router-image": METADATA["resources"]["router-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_active(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_is_deployed_when_relation_is_made_then_status_is_active(
    ops_test,
    build_and_deploy,
):
    await deploy_grafana_agent(ops_test)
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:logging",
        relation2=GRAFANA_AGENT_CHARM_NAME,
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
    )
