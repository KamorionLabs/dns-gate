"""MkDocs hooks: links from the docs to repository files outside docs/
(examples, OpenAPI document, chart) point to GitHub, so the Markdown stays
readable on GitHub and the site has no broken link."""

import posixpath
import re

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
