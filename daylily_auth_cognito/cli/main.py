import sys

from cli_core_yo.app import run

from .spec import spec


def main() -> None:
    sys.exit(run(spec))


if __name__ == "__main__":
    main()
