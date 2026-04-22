# Style

## Python

- Target: Python 3.12+
- `from __future__ import annotations` at the top of every module
- Type hints everywhere, including `-> None` returns
- Dataclasses (or `@dataclass(slots=True, frozen=True)` where natural) for
  domain objects
- Async over sync for all I/O — `asyncio.StreamReader`/`StreamWriter`,
  async MQTT wrapper
- Explicit byte widths when dealing with protocol values
  (`int.from_bytes(b, "big")`, never implicit)

## Ruff

See `pyproject.toml`:
- Line length 100
- Rule sets: `E`, `F`, `I`, `UP`, `W` (pycodestyle, pyflakes, isort,
  pyupgrade, warnings)
- Target py312

Run `ruff check --fix .` before committing.

## Mypy

`strict = true`. No `Any`, no untyped defs, no missing returns.

## Tests

- `pytest` + `pytest-asyncio` in auto mode
- Deterministic tests (CRC, framing, crypto) must have full coverage and
  pass before any live-device code is touched
- Integration tests that hit the Translator live are marked
  `@pytest.mark.live` and skipped by default

## Commits

- Conventional-commit-ish subjects: `feat:`, `fix:`, `chore:`, `docs:`,
  `test:`, `refactor:`
- One concern per commit

## Git / GitHub workflow

Terminology used in this repo:

- **"commit to repo"** / **"commit locally"** / **"just commit"** — local
  only. Runs `git commit`, nothing leaves the machine.
- **"push to GitHub"** / **"commit and push"** — includes `git push` to
  the remote.
- **"save it"** on its own is ambiguous; ask which is meant.

### Pre-push review gate (public repos)

`omnibus-bridge` and `omnibus-bridge-hassio` are **public**. Before every
push to either remote:

1. `git status` — confirm no unexpected files
2. `git diff --staged` — scan for AES keys, home-network IPs, paths with
   the username, anything from `captures/` or `.env`-shaped content
3. Wait for explicit confirmation before `git push`

A leaked secret in a public repo is indexed within hours; recovery means
rotating the AES keys on the Translator via OMNIBUS Software and
rewriting history with `git filter-repo`. The gate is mandatory even for
"obviously safe" changes.

### .gitignore discipline

`.gitignore` only applies to **untracked** files. Add patterns **before**
first staging a file — once committed, `.gitignore` no longer hides it
and `git rm --cached <path>` is required to untrack.

Current rules cover `.env`, `captures/`, `config/`, `logs/`, packet
captures, and scratch/debug scripts. If a new class of sensitive file
appears, update `.gitignore` first, then verify with
`git check-ignore -v <path>`.
