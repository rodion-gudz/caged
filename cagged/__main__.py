"""Default execution entry point if running the package via python -m."""

import sys

import cagged.cli


def cli():
    """Run caged from script entry point"""
    return cagged.cli.cli()


if __name__ == "__main__":
    sys.exit(cli())
