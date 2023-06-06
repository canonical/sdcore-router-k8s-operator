#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's router."""

import logging

from ops.charm import CharmBase
from ops.main import main

logger = logging.getLogger(__name__)


class RouterOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)


if __name__ == "__main__":  # pragma: no cover
    main(RouterOperatorCharm)
