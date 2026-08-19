"""Sphinx configuration for openid4vci."""

project = "openid4vci"
author = "eduTAP"
copyright = "2026, LMU München and the eduTAP contributors"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
}

html_theme = "furo"
html_title = "openid4vci"

exclude_patterns = ["_build"]
