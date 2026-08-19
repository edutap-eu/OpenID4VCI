.PHONY: help lint reformat test-local typecheck docs docs-linkcheck docs-live docs-clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

lint:  ## run all linters
	uvx prek run --all-files

reformat:  ## autoformat the code
	uvx ruff format src tests
	uvx ruff check --fix src tests

# Runs inside the project environment, not next to it: uvx would run ty in an
# environment of its own, where none of our dependencies exist and every import
# is unresolved. That passed locally only because a .venv happened to be lying
# around, and failed the moment CI ran it on a clean checkout.
typecheck:  ## run the type checker
	uv run --extra typecheck --extra test --extra mdoc ty check

test-local:  ## run the unit tests
	uv run --extra test pytest

docs:  ## build the documentation, warnings are errors
	uv run --extra docs sphinx-build -W -b html docs docs/_build/html

docs-linkcheck:  ## check that every link in the documentation resolves
	uv run --extra docs sphinx-build -b linkcheck docs docs/_build/linkcheck

docs-live:  ## build the documentation with autoreload
	uv run --extra docs --with sphinx-autobuild sphinx-autobuild docs docs/_build/html

docs-clean:  ## remove the built documentation
	rm -rf docs/_build
