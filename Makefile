src=src test

.PHONY: check
check:
	mypy ${src}
	pytest
	flake8 ${src}
	pylint ${src}
	isort --check ${src}
	black --check ${src}

.PHONY: format
format:
	isort ${src}
	black ${src}
