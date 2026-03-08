"""
setup_cython.py — WaveEye AXI-Lite Protocol Analyzer
======================================================

Compiles every production .py module to a native Cython extension.
The original .py source files are NOT modified or deleted; they remain
intact for the open-source GitHub repository.

Usage
-----
    # Compile in-place (extensions land next to their .py counterparts):
    python setup_cython.py build_ext --inplace

    # Or let build_release.py drive the full pipeline.

Platform output
---------------
    Windows  -> *.pyd
    Linux    -> *.so
    macOS    -> *.so  (or *.dylib depending on Python build)

Notes
-----
- __init__.py files are compiled too; Python 3.5+ honours compiled init modules.
- Files under  tests/  and  _archive_main_tool/  are never compiled.
- Parallel compilation uses all available CPU cores.
"""

import os
import sys
from pathlib import Path

from setuptools import Extension, setup

try:
    from Cython.Build import cythonize
    from Cython.Compiler import Options
except ImportError:
    print("ERROR: Cython is not installed.  Run:  pip install cython", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Cython global options
# ---------------------------------------------------------------------------
Options.annotate = False   # flip to True to generate .html inspection files

ROOT = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# Exclusion rules
# ---------------------------------------------------------------------------
# Any path component listed here causes the file to be skipped.
EXCLUDE_PATH_PARTS: set[str] = {
    "tests",
    "_archive_main_tool",
    "archive",
}

# Individual file names (anywhere in the tree) to skip.
EXCLUDE_FILENAMES: set[str] = {
    "conftest.py",
    "setup_cython.py",   # this file itself
    "build_release.py",
}


def _is_excluded(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDE_PATH_PARTS:
        return True
    if path.name in EXCLUDE_FILENAMES:
        return True
    return False


# ---------------------------------------------------------------------------
# Extension collector
# ---------------------------------------------------------------------------

def collect_extensions(source_dirs: list[str], root_files: list[str]) -> list[Extension]:
    """Walk source_dirs + root_files and return Cython Extension objects."""
    extensions: list[Extension] = []

    # Subdirectory modules
    for d in source_dirs:
        base = ROOT / d
        if not base.exists():
            print(f"  [warn] Directory not found, skipping: {base}")
            continue
        for py_file in sorted(base.rglob("*.py")):
            if _is_excluded(py_file):
                continue
            rel = py_file.relative_to(ROOT)
            module = str(rel.with_suffix("")).replace(os.sep, ".")
            # Use POSIX-style relative paths — required by bdist_wheel
            extensions.append(
                Extension(
                    name=module,
                    sources=[rel.as_posix()],
                    language="c",
                )
            )

    # Root-level files (main.py etc.)
    for fname in root_files:
        fpath = ROOT / fname
        if not fpath.exists():
            print(f"  [warn] Root file not found, skipping: {fname}")
            continue
        if _is_excluded(fpath):
            continue
        module = fname.replace(".py", "")
        extensions.append(
            Extension(
                name=module,
                sources=[fname],   # already relative (e.g. "main.py")
                language="c",
            )
        )

    return extensions


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------
SOURCE_DIRS = [
    "IR_backtracking",
    "Preprocessing",
]

ROOT_FILES = [
    "main.py",
]

extensions = collect_extensions(SOURCE_DIRS, ROOT_FILES)

print(f"[setup_cython] {len(extensions)} modules queued for compilation.")
for ext in extensions:
    print(f"  {ext.name}")

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
_cythonized = cythonize(
    extensions,
    # nthreads=0 runs in-process (no ProcessPoolExecutor) — required on
    # Windows where spawned worker processes crash on large files.
    # Use parallel workers only on Linux/macOS.
    nthreads=0 if sys.platform == "win32" else (os.cpu_count() or 4),
    compiler_directives={
        "language_level":        "3",
        "always_allow_keywords": True,
        # binding=True preserves Python signatures so inspect/help() still work
        "binding":               True,
        "embedsignature":        False,
    },
    quiet=False,
    # Rebuild only when source changes (cached by mtime)
    force=False,
)

# bdist_wheel requires *relative* source paths — patch any absolute paths
# that Cython may have introduced when computing .c file locations.
for _ext in _cythonized:
    _ext.sources = [
        os.path.relpath(s, ROOT) if os.path.isabs(s) else s
        for s in _ext.sources
    ]

setup(
    name="waveeye_axi_lite",
    version="1.0.0",
    ext_modules=_cythonized,
    zip_safe=False,
)
