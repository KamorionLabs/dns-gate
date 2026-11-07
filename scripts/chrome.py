#!/usr/bin/env python3
"""Render the shared chrome (chrome/head.html, header.html, footer.html) into
the static pages of the project site, between <!-- chrome:NAME --> markers.

  python3 scripts/chrome.py                    # write site/index.html, site/api.html
  python3 scripts/chrome.py --check            # fail if they are not up to date
  python3 scripts/chrome.py --version v0.9.0   # with the release in the footer (Pages build)

The documentation renders the same templates through overrides/main.html."""

import argparse
import pathlib
import re
import sys

import jinja2

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = {"site/index.html": "overview", "site/api.html": "api"}
MARK = re.compile(r"(<!-- chrome:(\w+) -->).*?(<!-- /chrome:\2 -->)", re.S)


def render(page: str, current: str, version: str) -> str:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT / "chrome"), keep_trailing_newline=False)
    ctx = {"root": "", "current": current, "version": version,
           "header_class": "", "header_attrs": "", "header_start": "", "header_search": ""}
    text = (ROOT / page).read_text()

    def fill(m):
        body = env.get_template(f"{m.group(2)}.html").render(ctx).strip()
        return f"{m.group(1)}\n{body}\n{m.group(3)}"

    return MARK.sub(fill, text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--version", default="")
    args = ap.parse_args()
    stale = []
    for page, current in PAGES.items():
        out = render(page, current, args.version)
        path = ROOT / page
        if args.check:
            if out != path.read_text():
                stale.append(page)
        else:
            path.write_text(out)
    if stale:
        print("chrome out of date, run python3 scripts/chrome.py:", ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
