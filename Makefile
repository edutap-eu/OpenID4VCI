.PHONY: help lint reformat test-local typecheck

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

lint:  ## run all linters
	uvx prek run --all-files

reformat:  ## autoformat the code
	uvx ruff format src tests
	uvx ruff check --fix src tests

typecheck:  ## run the type checker
	uvx ty check

test-local:  ## run the unit tests
	uv run --extra test pytest
