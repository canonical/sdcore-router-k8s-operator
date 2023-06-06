<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-router"><img src="https://charmhub.io/sdcore-router/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-router-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-router-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core Router Operator</h1>
</div>

A Charmed Operator for SD-Core's Router. 

## Pre-requisites

- Multus Kubernetes Addon

## Usage

```bash
juju deploy sdcore-router --trust
```

## Image

- **router**: `ubuntu:22.04`
