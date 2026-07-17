.DEFAULT_GOAL := help

.PHONY: help doctor setup test lint format format-check typecheck security audit \
        coverage coverage-html pre-commit migrations-check check clean update

help:            ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

doctor:          ## Check that all dev tools are installed and configured
	@echo "Checking development environment...\n"
	@ok=true; \
	printf "  %-24s" "Python (>=3.12)"; \
	if command -v python3 >/dev/null 2>&1; then \
		ver=$$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"); \
		maj=$$(echo "$$ver" | cut -d. -f1); \
		min=$$(echo "$$ver" | cut -d. -f2); \
		if [ "$$maj" -ge 3 ] && [ "$$min" -ge 12 ]; then \
			echo "OK ($$ver)"; \
		else \
			echo "WARN ($$ver — 3.12+ recommended)"; \
		fi; \
	else echo "MISSING"; ok=false; fi; \
	printf "  %-24s" "uv"; \
	if command -v uv >/dev/null 2>&1; then \
		echo "OK ($$(uv --version 2>&1 | head -1))"; \
	else echo "MISSING — install from https://docs.astral.sh/uv/"; ok=false; fi; \
	printf "  %-24s" "pre-commit hooks"; \
	if [ -f .git/hooks/pre-commit ] && grep -q pre-commit .git/hooks/pre-commit 2>/dev/null; then \
		echo "OK"; \
	else echo "NOT INSTALLED — run: make setup"; ok=false; fi; \
	printf "  %-24s" "commit-msg hook"; \
	if [ -f .git/hooks/commit-msg ] && grep -q pre-commit .git/hooks/commit-msg 2>/dev/null; then \
		echo "OK"; \
	else echo "NOT INSTALLED — run: make setup"; ok=false; fi; \
	printf "  %-24s" "Dependencies (uv)"; \
	if [ -d .venv ] && uv run python -c "import django" 2>/dev/null; then \
		echo "OK"; \
	else echo "NOT SYNCED — run: uv sync"; ok=false; fi; \
	echo ""; \
	if $$ok; then \
		echo "All good! Ready to develop."; \
	else \
		echo "Some issues found. Run 'make setup' to fix most of them."; \
		exit 1; \
	fi

setup:           ## Set up local dev environment (install deps, hooks)
	uv sync
	uv run pre-commit install
	uv run pre-commit install --hook-type commit-msg

test:            ## Run tests (package pytest suite + example_project store tests)
	uv run pytest
	uv run python example_project/manage.py test store

lint:            ## Run ruff linter
	uv run ruff check .

format:          ## Run ruff formatter
	uv run ruff format .

format-check:    ## Check formatting without modifying files
	uv run ruff format --check .

typecheck:       ## Run mypy type checker
	uv run mypy sso_portal_client/ example_project/

security:        ## Run bandit security linter
	uv run bandit -c pyproject.toml -r sso_portal_client/ example_project/

audit:           ## Scan dependencies for known vulnerabilities
	uv run pip-audit

coverage:        ## Run tests with coverage report
	uv run coverage run -m pytest
	uv run coverage run --append example_project/manage.py test store
	uv run coverage report

coverage-html:   ## Run tests with coverage HTML report
	uv run coverage run -m pytest
	uv run coverage run --append example_project/manage.py test store
	uv run coverage html

pre-commit:      ## Run all pre-commit hooks
	uv run pre-commit run --all-files

migrations-check: ## Check for missing migrations (example_project)
	uv run python example_project/manage.py makemigrations --check --dry-run

clean:           ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/ .mypy_cache/ .ruff_cache/ .pytest_cache/ build/ dist/ *.egg-info

update:          ## Update dependencies to latest compatible versions
	uv sync --upgrade
	uv run pre-commit autoupdate

check:           ## Run all checks (lint, format, typecheck, security, audit, migrations, test)
	@failed=0; \
	echo "==> ruff check"; uv run ruff check . || failed=$$((failed + 1)); \
	echo "==> ruff format"; uv run ruff format --check . || failed=$$((failed + 1)); \
	echo "==> django check"; uv run python example_project/manage.py check --fail-level WARNING || failed=$$((failed + 1)); \
	echo "==> migrations check"; $(MAKE) --no-print-directory migrations-check || failed=$$((failed + 1)); \
	echo "==> mypy"; uv run mypy sso_portal_client/ example_project/ || failed=$$((failed + 1)); \
	echo "==> bandit"; uv run bandit -c pyproject.toml -r sso_portal_client/ example_project/ || failed=$$((failed + 1)); \
	echo "==> pip-audit"; uv run pip-audit || failed=$$((failed + 1)); \
	echo "==> pytest + coverage"; ( \
		uv run coverage run -m pytest && \
		uv run coverage run --append example_project/manage.py test store && \
		uv run coverage report \
	) || failed=$$((failed + 1)); \
	echo ""; \
	if [ $$failed -ne 0 ]; then \
		echo "$$failed check(s) failed."; exit 1; \
	else \
		echo "All checks passed."; \
	fi
