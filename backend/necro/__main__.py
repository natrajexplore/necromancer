"""Allow ``python -m necro`` as an alternative to the ``necro`` console script."""

import sys

from necro.cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
