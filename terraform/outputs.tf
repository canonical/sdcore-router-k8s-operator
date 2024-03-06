# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.router.name
}

# Required integration endpoints

output "logging_endpoint" {
  description = "Name of the endpoint used to integrate with the Logging provider."
  value       = "logging"
}
