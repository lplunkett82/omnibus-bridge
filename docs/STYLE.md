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
- No push to any remote until Phase 6
