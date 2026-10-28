import sys


def main(argv, _host_for_test=None) -> int:
    if "--self-check" in (argv or []):
        from .states import KNOWN_GOOD_SHA, TARGET_SHA

        print(TARGET_SHA)
        print(KNOWN_GOOD_SHA)
        return 0
    print("ACTIVATION_NOT_AUTHORIZED", file=sys.stderr)
    return 2
