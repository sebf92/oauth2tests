"""
Markdown documentation rendering pipeline for the ``/docs/*`` Flask routes.

This module owns:
  • ``DOCS_MANIFEST``  — the list of doc pages exposed in the UI
  • ``DOCS_DIR``       — filesystem path (env-overridable) where the .md files live
  • ``_PYGMENTS_CSS``  — code-block CSS generated once at import time
  • ``_MERMAID_FENCE_RE``  — regex that intercepts ```mermaid blocks
  • ``_render_doc(filename)`` — read a .md file, convert to (content_html, toc_html)

The Flask routes ``/docs`` and ``/docs/<slug>`` stay in ``app.py`` since they
are trivial wrappers; everything else they need is imported from here.

Adding a new doc page
─────────────────────
1. Drop a ``<slug>.md`` file into ``DOCS_DIR``.
2. Append an entry to ``DOCS_MANIFEST`` with ``slug``, ``file``, ``title``,
   ``icon`` (Bootstrap Icons class), ``color``, ``badge``, ``description``.

No route changes needed.
"""

import html as _html
import os
import re as _re

import markdown as _markdown
from markupsafe import Markup


# Filesystem location of the markdown files.  In Docker the host's ./docs is
# bind-mounted to /app/docs; the env var lets a developer override for local
# development against a checkout outside the container.
DOCS_DIR = os.getenv(
    "DOCS_DIR",
    # Development fallback: docs/ sits next to client-app/ in the project root.
    os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "docs")),
)


DOCS_MANIFEST = [
    {
        "slug":        "architecture",
        "file":        "architecture.md",
        "title":       "Architecture",
        "icon":        "bi-diagram-3-fill",
        "color":       "primary",
        "badge":       "System Design",
        "description": "Components, network topology, JWT structure, and security model",
    },
    {
        "slug":        "oauth2-flows",
        "file":        "oauth2-flows.md",
        "title":       "OAuth2 / OIDC Flows",
        "icon":        "bi-arrow-repeat",
        "color":       "success",
        "badge":       "Core Reference",
        "description": "All eleven flows in detail — diagrams, request/response examples, and key differences",
    },
    {
        "slug":        "spiffe-oauth2",
        "file":        "spiffe-oauth2.md",
        "title":       "SPIFFE / SPIRE + OAuth2",
        "icon":        "bi-fingerprint",
        "color":       "info",
        "badge":       "Workload Identity",
        "description": "JWT-SVIDs, RFC 7523 private_key_jwt client auth, and the legacy bridge pattern",
    },
    {
        "slug":        "obo-manual-setup",
        "file":        "obo-manual-setup.md",
        "title":       "OBO Manual Setup",
        "icon":        "bi-wrench-adjustable-circle-fill",
        "color":       "warning",
        "badge":       "How-To Guide",
        "description": "Step-by-step guide for manually configuring On-Behalf-Of token exchange in KC 26.2+",
    },
    {
        "slug":        "keycloak-brokering",
        "file":        "keycloakbrokeringtoping.md",
        "title":       "Keycloak → Ping Brokering",
        "icon":        "bi-arrow-left-right",
        "color":       "danger",
        "badge":       "Identity Brokering",
        "description": "How Keycloak brokers authentication to PingFederate / PingOne — sequence diagrams and 23-step flow walkthrough",
    },
    {
        "slug":        "agentic-ai",
        "file":        "agentic-ai.md",
        "title":       "Agentic AI + MCP",
        "icon":        "bi-cpu",
        "color":       "info",
        "badge":       "Agentic AI",
        "description": "Four patterns for AI agents accessing a protected MCP server — Client Secret, SPIFFE workload identity, X.509 certificate, and user-delegated OBO with rescoping. Sequence diagrams + implementation notes.",
    },
]


# Generate Pygments CSS once at import time; consumers inject it into
# docs_page.html via the pygments_css context var.  An ImportError or other
# failure here results in empty CSS so the page still renders (just without
# syntax-highlighted code blocks).
try:
    from pygments.formatters import HtmlFormatter as _HtmlFormatter
    _PYGMENTS_CSS = _HtmlFormatter(style="monokai").get_style_defs(".highlight")
except Exception:
    _PYGMENTS_CSS = ""


# Pre-compiled regex for extracting ```mermaid … ``` fenced blocks from markdown.
_MERMAID_FENCE_RE = _re.compile(r'```mermaid\s*\n(.*?)```', _re.DOTALL)


def _render_doc(filename: str):
    """
    Read a markdown file from DOCS_DIR and render it to HTML + TOC.

    Returns (content_html, toc_html) as Markup objects (already safe for Jinja2).

    Mermaid diagram pipeline
    ────────────────────────
    Python-markdown's fenced_code extension would turn ```mermaid blocks into
    <pre><code> blocks, which Mermaid.js cannot process.  We must intercept them
    before markdown runs.  The steps are:

      1. _MERMAID_FENCE_RE extracts the raw diagram source from each ```mermaid block.
      2. _html.escape() HTML-encodes the source (<, >, &, ").  This is critical:
         angle brackets in diagram labels (e.g. <token>) would be stripped by the
         browser HTML parser if left as-is, breaking Mermaid syntax.
      3. The escaped source is wrapped in <div class="mermaid">...</div>.
         Python-markdown passes block-level HTML through unchanged.
      4. In the browser, Mermaid.js reads element.textContent, which decodes HTML
         entities back to the original characters (&lt; → <) before parsing.
      5. docs_page.html conditionally loads Mermaid.js (ESM CDN build) only when
         the rendered HTML contains at least one mermaid div.
    """
    path = os.path.join(DOCS_DIR, filename)
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return (
            Markup("<p class='text-danger'><strong>Documentation file not found.</strong><br>"
                   f"Expected path: <code>{path}</code></p>"),
            Markup(""),
        )
    raw = _MERMAID_FENCE_RE.sub(
        lambda m: f'<div class="mermaid">\n{_html.escape(m.group(1))}\n</div>', raw
    )
    md = _markdown.Markdown(
        extensions=["tables", "fenced_code", "codehilite", "toc", "attr_list"],
        extension_configs={
            "codehilite": {"css_class": "highlight", "use_pygments": True},
            "toc": {"title": "", "toc_depth": "2-2", "permalink": True,
                    "permalink_class": "toc-anchor", "permalink_title": "¶"},
        },
    )
    return Markup(md.convert(raw)), Markup(md.toc)
