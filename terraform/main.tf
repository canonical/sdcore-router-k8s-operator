# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "router" {
  name  = var.app_name
  model = var.model_name

  charm {
    name    = "sdcore-router-k8s"
    channel = var.channel
  }
  config = var.config

  units  = 1
  trust  = true
}
