"""Allows `python -m triage`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
