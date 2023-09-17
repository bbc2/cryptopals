src=src test

.PHONY: help
help:
	@# Taken from https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: check-lint
check-lint:  ## Lint and check typing.
	dmypy run -- ${src}
	ruff check ${src}

.PHONY: check-test
check-test:  ## Run all the tests.
	pytest

.PHONY: check-format
check-format:  ## Check formatting.
	ruff check --select I --diff ${src}
	black --check ${src}

.PHONY: check  ## Check everything.
check: check-lint check-test check-format

.PHONY: format
format:  ## Format the source code.
	ruff --select I --fix ${src}
	black ${src}
