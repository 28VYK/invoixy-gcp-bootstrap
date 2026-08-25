"""Entrypoint for python -m invoixy_bootstrap."""

import sys
from invoixy_bootstrap.cli import main

if __name__ == "__main__":
    sys.exit(main())
