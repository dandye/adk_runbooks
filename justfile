# Justfile for Sphinx documentation

# You can set these variables from the command line (e.g., just O="-W" html).
SOURCEDIR := "rules-bank"
BUILDDIR := "build"
SPHINXOPTS := "-c " + SOURCEDIR
SPHINXBUILD := "sphinx-build"
O := ""

# Put it first so that "just" without argument is like "just help".
help:
  @{{ SPHINXBUILD }} -M help "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }}

# Build HTML documentation
html *opts="":
  @{{ SPHINXBUILD }} -M html "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

# Clean Sphinx build directory
clean *opts="":
  @{{ SPHINXBUILD }} -M clean "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

# Route any Sphinx builder target to sphinx-build -M (e.g., just build dirhtml)
build target *opts="":
  @{{ SPHINXBUILD }} -M {{ target }} "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}
