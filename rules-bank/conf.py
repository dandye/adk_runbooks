# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Rules Bank'
copyright = '2025, Your Name/Organization'  # Please update this
author = 'Your Name/Organization'  # Please update this
# release = '0.1' # Update as needed
# version = '0.1.0' # Update as needed

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'myst_parser',  # Using myst_parser directly for diagnostics
    'sphinx.ext.autodoc',
    'sphinx_autodoc_typehints',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx_copybutton',
    'sphinx_design',
    'sphinxcontrib.mermaid',
    'sphinx_book_theme',
]

templates_path = ['_templates'] # Relative to this conf.py file
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'README.md']

# The master toctree document.
# For Sphinx 4.0+, root_doc is preferred over master_doc.
# Sphinx will look for 'index.md' or 'index.rst' etc. based on source_suffix
root_doc = 'index'

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown', # if you have .txt files as markdown
    '.md': 'markdown',
}

# Explicitly define source parsers (though myst_nb should handle .md)
# from myst_parser.sphinx_parser import MystParser # Not usually needed with myst_nb
# source_parsers = {
#    '.md': MystParser,
# }


# -- MyST Parser Configuration -----------------------------------------------
# https://myst-parser.readthedocs.io/en/latest/configuration.html
# https://myst-nb.readthedocs.io/en/latest/configuration.html

myst_enable_extensions = [
    "colon_fence",    # For directives like ```{directive}
    "dollarmath",     # For LaTeX math like $E=mc^2$
    "linkify",        # Auto-detect and create links for URLs (requires linkify-it-py)
    "smartquotes",    # Convert straight quotes to curly quotes
    "tasklist",       # For checklists like - [x] Task
    "substitution",   # For defining and using substitutions
]
myst_heading_anchors = 3  # Auto-generate header anchors up to level 3
# myst_substitutions = {
#   "project_name": project
# }

# For myst_nb (if you use .ipynb files or executable code blocks in .md)
nb_execution_mode = "off"  # "off", "force", "auto", "cache"
# nb_execution_timeout = 30
# nb_output_stderr = "show"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_book_theme'
html_static_path = ['_static'] # Relative to this conf.py file. For custom CSS, JS.
html_logo = "_static/adk_runbooks_logo.png"
# html_favicon = "_static/favicon.ico"

html_theme_options = {
    "repository_url": "https://github.com/dandye/adk_runbooks",
    "repository_branch": "main",
    "path_to_docs": "rules-bank",  # Path from repository root to this sphinx source dir
    "use_edit_page_button": True,
    "use_issues_button": True,
    "use_repository_button": True,
    "home_page_in_toc": True,
    # "announcement": "<em>Important</em> announcement!",
}

# -- Intersphinx configuration ---------------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}

# -- Todo extension configuration ------------------------------------------
todo_include_todos = True

# -- Mermaid extension configuration ---------------------------------------
# mermaid_output_format = 'png' # 'png' or 'svg', png requires mermaid CLI

# -- Copybutton configuration ---------------------------------------------
# copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
# copybutton_prompt_is_regexp = True

# Custom CSS (optional)
# Create a file like rules-bank/_static/custom.css and uncomment below
# def setup(app):
#    app.add_css_file('custom.css')
