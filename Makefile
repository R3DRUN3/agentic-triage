.PHONY: install lint test sast run docker

install:
	python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt

lint:
	ruff check . && mypy

test:
	pytest --cov=app

sast:
	bandit -r app -c pyproject.toml

run:
	python -m app.main

docker:
	docker build -t agentic-triage:local . && docker run --rm -p 8000:8000 agentic-triage:local