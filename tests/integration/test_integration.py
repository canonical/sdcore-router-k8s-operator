#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APPLICATION_NAME = METADATA["name"]
GRAFANA_AGENT_CHARM_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_CHARM_CHANNEL = "latest/stable"


async def deploy_grafana_agent(ops_test: OpsTest):
    """Deploy the grafana-agent charm."""
    assert ops_test.model
    await ops_test.model.deploy(
        GRAFANA_AGENT_CHARM_NAME,
        application_name=GRAFANA_AGENT_CHARM_NAME,
        channel=GRAFANA_AGENT_CHARM_CHANNEL,
    )


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, request):
    """Deploy the charm-under-test."""
    charm = Path(request.config.getoption("--charm_path")).resolve()
    resources = {
        "router-image": METADATA["resources"]["router-image"]["upstream-source"],
    }
    assert ops_test.model
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_active(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_is_deployed_when_relation_is_made_then_status_is_active(
    ops_test: OpsTest, deploy
):
    assert ops_test.model
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
