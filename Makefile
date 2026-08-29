# ---------------------------------------------------------------------------
# Crucible task runner
#
# One entry point per thing a person actually does. If a command needs to be
# remembered, it belongs here instead.
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help
.PHONY: help setup check lint format types imports test test-all contracts \
        airgap-check corpus lab-up lab-down bundle clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- development -----------------------------------------------------------

setup: ## Install backend and frontend dependencies for development
	cd backend && pip install -e ".[dev,ai]"
	cd frontend && npm ci

check: contracts test ## Everything CI runs, locally

check-full: lint types imports contracts test ## Adds ruff and mypy (needs the dev extra)

lint: ## Ruff
	cd backend && ruff check .
	cd backend && ruff format --check .

format: ## Apply formatting
	cd backend && ruff format .
	cd backend && ruff check --fix .

types: ## Mypy
	cd backend && mypy crucible

imports: ## Enforce the IR dependency rule from ADR 0001
	cd backend && lint-imports

# --- contracts -------------------------------------------------------------

contracts: ## Validate every schema, every rule file and the worked IR example
	check-jsonschema --check-metaschema schemas/ir/v1.0.0/ir.schema.json
	check-jsonschema --check-metaschema schemas/rule/v1.0.0/rule.schema.json
	check-jsonschema --schemafile schemas/ir/v1.0.0/ir.schema.json \
	  schemas/ir/v1.0.0/example.cisco-ios.ir.json
	check-jsonschema --schemafile schemas/rule/v1.0.0/rule.schema.json rules/cis/*.yaml

# --- tests -----------------------------------------------------------------

test: ## Run the suite (pytest if installed, standalone runner otherwise)
	cd backend && python tests/run_tests.py

test-pytest: ## Run under pytest, skipping sandbox and model tests
	cd backend && pytest -m "not sandbox and not model"

test-all: ## Everything, including sandbox and model tests
	cd backend && pytest

airgap-check: ## Fail if a cloud SDK or external asset host appears anywhere
	@bash scripts/check-airgap.sh

# --- running it ------------------------------------------------------------

demo: ## Audit the bundled five-vendor fixtures and write reports to ./reports
	cd backend && python -m crucible.api.cli audit tests/fixtures/devices 	  --rules ../rules/cis --out ../reports

serve: ## Start the API and the audit console on http://127.0.0.1:8000
	cd backend && uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000

verify: ## Verify the ledger produced by `make demo`
	cd backend && python -m crucible.api.cli verify ../reports/ledger.jsonl

# --- corpus and labs -------------------------------------------------------

corpus: ## Report corpus progress against the Phase 0 target
	@bash scripts/corpus-status.sh

lab-up: ## Boot the corpus generation topology
	containerlab deploy -t labs/corpus/multivendor.clab.yml

lab-down: ## Tear it down
	containerlab destroy -t labs/corpus/multivendor.clab.yml --cleanup

# --- packaging -------------------------------------------------------------

bundle: ## Build the offline installation bundle
	@bash scripts/build-offline-bundle.sh

clean: ## Remove build and cache artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf backend/.pytest_cache backend/.mypy_cache backend/.ruff_cache
	rm -rf frontend/.next frontend/out
