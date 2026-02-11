# ── Variables ───────────────────────────────────────────────────────────────
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH       := $(shell git branch --show-current 2>/dev/null || echo "detached")
TIMESTAMP    := $(shell date +%Y%m%d_%H%M%S)
TAG          := $(TIMESTAMP)_$(COMMIT)

CHECKPOINT_DIR := .local_benchmark/checkpoints
CORPUS_DIR     := .local_benchmark/corpus
EVAL_DIR       := evals/skills

# ── Phony targets ──────────────────────────────────────────────────────────
.PHONY: help benchmark benchmark-eval benchmark-corpus test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Benchmark suite ────────────────────────────────────────────────────────
benchmark: benchmark-eval benchmark-corpus ## Run full benchmark suite

benchmark-eval: ## Run eval-skills benchmark (~30 s)
	@mkdir -p $(CHECKPOINT_DIR)
	@echo "╭─ eval benchmark  [$(TAG)] ─╮"
	uv run python evals/runners/benchmark_runner.py \
		--eval-dir $(EVAL_DIR) \
		--output $(CHECKPOINT_DIR)/$(TAG)_eval.json
	@echo "╰─ saved → $(CHECKPOINT_DIR)/$(TAG)_eval.json ─╯"

benchmark-corpus: ## Run corpus policy benchmark (~9 min)
	@mkdir -p $(CHECKPOINT_DIR)
	@echo "╭─ corpus benchmark  [$(TAG)] ─╮"
	uv run python evals/runners/policy_benchmark.py \
		--corpus $(CORPUS_DIR) \
		--output $(CHECKPOINT_DIR)/$(TAG)_policy.md \
		--json-output $(CHECKPOINT_DIR)/$(TAG)_policy.json
	@echo "╰─ saved → $(CHECKPOINT_DIR)/$(TAG)_policy.{md,json} ─╯"

# ── Dev tasks ──────────────────────────────────────────────────────────────
test: ## Run test suite
	uv run python -m pytest tests/ -x -q

lint: ## Run linters (ruff check + format)
	uv run ruff check . --fix
	uv run ruff format .

clean: ## Remove __pycache__ and .pytest_cache dirs
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
