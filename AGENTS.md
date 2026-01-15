# Repository Guidelines

## Project Structure & Module Organization
- `docs/` holds design notes; see `docs/design_doc.md` for the intended architecture and data formats.
- `src/` exists but is currently empty.
- `pyproject.toml` defines the project metadata and Python version (3.11+).
- The design doc proposes future locations like `scripts/cve_watch.py`, `watchlist.yml`, `posted/`, and `.github/workflows/cve_watch.yml`. Create those as you implement the bot.

## Build, Test, and Development Commands
- `python -m venv .venv` creates a local virtual environment.
- `python -m pip install -e .` installs the package in editable mode once modules are added.
- `python scripts/cve_watch.py` (planned) runs the CVE fetch/post flow locally; ensure required config and secrets are set first.

## Coding Style & Naming Conventions
- Use 4-space indentation and PEP 8 formatting.
- Prefer `snake_case` for functions/variables and `PascalCase` for classes.
- Keep modules small and focused (e.g., `nvd_client.py`, `slack_notifier.py`).

## Testing Guidelines
- No test framework is configured yet.
- When adding tests, place them under `tests/` and use `test_*.py` naming so `python -m pytest` can discover them.
- Include coverage for API response parsing, deduplication, and Slack payload formatting.

## Commit & Pull Request Guidelines
- This repo has no commit history yet, so there is no established convention.
- Use concise, imperative commit messages (e.g., "Add NVD API client", "Fix CVE dedup logic").
- PRs should explain intent, list key changes, and note any configuration or secret requirements.

## Security & Configuration Tips
- Expect to use GitHub Actions secrets such as `NVD_API_KEY` and `SLACK_WEBHOOK_URL` per `docs/design_doc.md`.
- Never commit webhook URLs or API keys to the repository.
- Posted-state files (e.g., `posted/posted__YYYYMMDD_*.json`) should be treated as data artifacts and reviewed for sensitive content before sharing.
