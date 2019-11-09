src=src test

.PHONY: check
check:
	mypy ${src}
	pytest
	flake8 ${src}
	pylint ${src}
	isort --check --recursive ${src}
	black --check ${src}

.PHONY: format
format:
	isort --recursive ${src}
	black ${src}
