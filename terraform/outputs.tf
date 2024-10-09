# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.router.name
}

output "requires" {
  value = {
    logging = "logging"
  }
}
