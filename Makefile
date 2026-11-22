.PHONY: test lint build publish docker

test:
	pytest

lint:
	ruff check .

build:
	python -m build

publish: build
	twine upload dist/*

docker:
	docker build -t tchabio01/vulnscan:latest .
