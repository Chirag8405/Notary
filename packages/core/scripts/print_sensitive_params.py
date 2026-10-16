"""Print the sensitive-parameter table as Markdown for the two-reviewer review.

This script lives outside `notary_core` so the package itself stays free of I/O.
"""

import sys

from notary_core.policy.sensitive_params import DEFAULT_POLICY, render_markdown


def main() -> None:
    sys.stdout.write(render_markdown(DEFAULT_POLICY))


if __name__ == "__main__":
    main()
