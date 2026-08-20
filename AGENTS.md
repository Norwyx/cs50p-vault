# AGENTS.md

CS50P Vault: a small CLI password manager (CS50P final project). Python 3.10+, stdlib SQLite + `rich`, `art`, `argon2-cffi`, `cryptography`, `pyperclip`. No CI, no lint/typecheck/format config.

## Commands

- Install (end users): `pip install .` then run `cs50p-vault` — console script from `pyproject.toml` (`[project.scripts]`).
- Run from source: `pip install -r requirements.txt && python src/main.py` — creates `vault.db` in the CWD; never commit it (gitignored).
- Dev install: `pip install -e ".[dev]"` (the `dev` extra is the only place pytest lives; `requirements.txt` won't run tests).
- Tests: `pytest` from the repo root.
- No other dev commands exist (no linter, formatter, or typecheck). Do not invent them.

## Gotchas

- Packaging: `[tool.setuptools] packages = ["src"]` is **explicit** on purpose — `find_packages(where="src")` returns `[]` because the layout is flat (`src/__init__.py` directly at the layout root), and an empty wheel breaks the `cs50p-vault` entry point. If you add/remove modules, keep this list in sync. Don't move code out of `src/` without updating the entry point, README, and tests.
- Import style: `src/main.py` uses dual-mode imports (`import database` with a `from src import ...` fallback) so it works both via `python src/main.py` (script dir on `sys.path`) and as the installed `cs50p-vault` entry point. Tests use `from src import ...` only. Don't unify into one style without updating the other half.
- Slow crypto is inherent: Argon2 hashing and PBKDF2 (480k iterations, `security.py:85`) take ~0.5–2s each. `tests/test_database.py` computes a module-level Argon2 hash at import, so the suite is slow. Avoid adding loops over `hash_password`/`derive_key` in code or tests.
- DB error convention: `database.py` functions print a rich error to the console and return `None`/`False` instead of raising. `main.py` handles these return values; new callers must too.
- `get_db_connection` may return `None` on failure (src/database.py:26) — guard before use.
- Menu dispatch in `main()` is a dict of callables (`main.py:384`); new menu items must be added both to the dict and to `print_menu()`.
- Credentials table: `service` is UNIQUE — duplicate inserts return `False`, not an error (src/database.py:159).
- `set_master_password`/`update_master_password` use `INSERT OR REPLACE ... id = 1`, so the password row is idempotent — don't revert to bare `INSERT` or stale rows accumulate and `get_master_password` silently reads the first.
- `update_credential`/`delete_credential` return `bool` (rowcount-based) so callers can detect a missing service.
- `change_master_password` (main.py) re-encrypts **all** credentials with the new key and swaps the in-memory key. If you change that flow, keep it atomic-ish: decrypt everything into memory first and abort (leaving the DB untouched) if any row fails `InvalidToken`.

## Architecture

- `src/main.py` — `Vault` class (all user-facing ops), menu loop, clipboard via `pyperclip` (auto-cleared after 10s), unlock throttling after repeated failures; encryption key held in memory only while unlocked.
- `src/database.py` — all SQLite CRUD, three tables (`master_password`, `credentials`, `user`), `sqlite3.Row` factory.
- `src/security.py` — Argon2 hash/verify, PBKDF2 key derivation, Fernet encrypt/decrypt. Keep all crypto here.
- `tests/` — plain pytest functions using in-memory DBs (`:memory:`), no fixtures/mocks; `tests/test_vault.py` exercises the `Vault` class with `monkeypatch`ed `getpass`.