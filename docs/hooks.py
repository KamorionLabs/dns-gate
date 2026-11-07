"""MkDocs hooks: links from the docs to repository files outside docs/
(examples, OpenAPI document, chart) point to GitHub, so the Markdown stays
readable on GitHub and the site has no broken link."""

import os
import pathlib
import posixpath
import re
import shutil

import jinja2

REPO_BLOB = "https://github.com/KamorionLabs/dns-gate/blob/main/"
LINK = re.compile(r"(\]\()([^)\s#]+)((?:#[^)\s]*)?\))")


def on_page_markdown(markdown, page, config, files):
    page_dir = posixpath.dirname(page.file.src_uri)

    def rewrite(m):
        target = m.group(2)
        if "://" in target or target.startswith(("/", "mailto:")):
            return m.group(0)
        path = posixpath.normpath(posixpath.join("docs", page_dir, target))
        if path.startswith("docs/"):
            return m.group(0)
        return m.group(1) + REPO_BLOB + path + m.group(3)

    return LINK.sub(rewrite, markdown)


# The site chrome: header and footer templates in chrome/, shared with the
# landing page and the API reference (scripts/chrome.py), and site/chrome.css.
REPO = pathlib.Path(__file__).resolve().parent.parent


def on_config(config):
    config.extra["gate_version"] = os.environ.get("DNS_GATE_VERSION", "")
    return config


def on_env(env, config, files):
    env.loader = jinja2.ChoiceLoader([env.loader, jinja2.FileSystemLoader(str(REPO / "chrome"))])
    return env


def on_post_build(config):
    shutil.copyfile(REPO / "site" / "chrome.css", pathlib.Path(config["site_dir"]) / "chrome.css")
