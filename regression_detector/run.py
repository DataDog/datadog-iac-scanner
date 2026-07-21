#!/usr/bin/env python3
"""CI entrypoint for the IaC scanner performance-regression benchmark."""

# Direct script execution intentionally imports the sibling package.
from benchmark.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
