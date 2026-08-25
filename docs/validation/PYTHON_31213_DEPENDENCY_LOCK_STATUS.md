# CPython 3.12.13 Dependency Lock Status

> Dated dependency-lock validation record. The 726-test result below applies
> to the exact lock-validation tree and environment observed on 24 August; it
> is not the final candidate regression. See `V2_CANONICAL_STATUS.md` for the
> latest repository-wide result.

Status date: 2026-08-24

## Target and scope

The target is CPython 3.12.13 on 64-bit Windows, with cache tag
`cpython-312` and platform tag `win-amd64`.

Static import inspection of the canonical library/CLI identifies one direct
production package: `cryptography`. Pytest is the sole additional direct test
package. The canonical direct production declaration is `requirements.txt`.

`requirements-production.lock.txt` contains the complete three-package
production closure. `requirements-test.lock.txt` contains the complete
nine-package production-plus-test closure. Both files pin every version, require
binary artifacts, enable pip hash checking, and contain the observed SHA-256
of the exact wheel selected for this target.

## Resolution source and compatibility

Resolution used pip 26.2.1 against the official
`https://pypi.org/simple` index with `--only-binary=:all:`, implementation
`cp`, Python version `3.12`, ABI `cp312`, and platform `win_amd64`.
Official wheel metadata declares Python 3.12 compatible for both direct
packages. Cryptography's selected `cp311-abi3` wheel is ABI3-compatible with
CPython 3.12; `cffi` uses a target-specific `cp312` wheel.

The downloaded wheel bytes were independently SHA-256 hashed before the lock
files were written. The cryptography and pycparser artifacts reproduce the
hashes recorded by the earlier CPython 3.11 resolution. The target-specific
hash is:

- `cffi-2.1.1-cp312-cp312-win_amd64.whl`:
  `f53e442b08449d42821fa4a4fba000095af9f62742a500f978a9f557ec44339a`
A separate `--no-cache-dir` download fetched all nine test-closure artifacts and
their metadata afresh from the official index. Recomputed SHA-256 values
matched all nine test-lock entries with zero mismatches.

## Assurance boundary

These files are exact target installation locks; they do not create the
separately governed `python-dependencies.lock.json` assurance artifact. Schema
`sbp.lex.v2.python-dependency-lock/3` requires separately pinned PTDE
accepted-attempt and local-trust accepted-package history sequence/digest pairs,
plus an exact predecessor-lock pin. Schema `/2` is rejected. The offline builder
derives the dependency graph from exact hashed wheel metadata, writes a new
canonical artifact exclusively, and immediately revalidates it. The genuine
history snapshots, independent pins and final freeze binding remain external;
no history digest, lock sequence, admission, or production authority has been
invented.

## Validation

The clean workspace-contained `runtime_artifacts/python31213-cli-venv`
environment uses CPython 3.12.13. It was installed offline from the
repository-local CPython 3.12 wheelhouse using
`--no-index --no-deps --require-hashes -r requirements-test.lock.txt`.
All nine locked packages installed successfully.

Validation results:

- `pip check`: `No broken requirements found.` (exit 0).
- Focused dependency-lock tests: four passed, including byte-for-byte SHA-256
  verification of both downloaded wheelhouses.
- Canonical `main.run_v2`, compatibility wrapper and CLI import under CPython
  3.12.13: pass.
- Complete stable-tree suite with every repository test file enumerated
  explicitly: 726 passed and 269 subtests passed in 665.57 seconds (exit 0),
  with zero skips and zero deselections.

These are mutable development-environment results, not immutable release or
independent validation evidence.
