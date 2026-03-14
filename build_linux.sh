#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  WaveEye — Linux build script
#  Run from the project root (where main.py lives):
#    bash build_linux.sh
#
#  Works in native Linux or WSL (Windows Subsystem for Linux).
#  Output: standalone/WaveEye-linux/  +  standalone/WaveEye-linux.zip
# ─────────────────────────────────────────────────────────────

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/standalone"
OUT="$DIST/WaveEye-linux"
ZIP="$DIST/WaveEye-linux.zip"

echo
echo "[BUILD] WaveEye Linux executable"
echo "[BUILD] Project root : $ROOT"
echo "[BUILD] Output       : $OUT"
echo

# ── Prerequisites check ──────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.10+ first."
    exit 1
fi

if ! python3 -c "import PyInstaller" &>/dev/null; then
    echo "[ERROR] pyinstaller not found. Run:  pip install pyinstaller"
    exit 1
fi

# ── Clean previous build ─────────────────────────────────────
rm -rf "$OUT" "$ZIP" "$ROOT/dist/waveeye"

# ── Run PyInstaller ──────────────────────────────────────────
cd "$ROOT"
python3 -m PyInstaller waveeye.spec \
    --distpath "$DIST/temp_dist" \
    --workpath "$ROOT/build/pyinstaller_work" \
    --noconfirm

# ── Rename output folder ─────────────────────────────────────
mv "$DIST/temp_dist/waveeye" "$OUT"
rm -rf "$DIST/temp_dist"

# ── Mark executable ──────────────────────────────────────────
chmod +x "$OUT/waveeye"

# ── Remove stale Cython .so files that shadow updated .py source ──────────
echo "[BUILD] Removing shadowed Cython .so files..."
find "$OUT/_internal" -name "*.so" | while read sofile; do
    pyfile="${sofile%.cpython-*-linux-gnu.so}.py"
    if [ -f "$pyfile" ]; then
        rm "$sofile"
    fi
done

# ── Zip it ───────────────────────────────────────────────────
echo "[BUILD] Creating zip archive..."
cd "$DIST"
zip -r "$(basename "$ZIP")" "$(basename "$OUT")"

echo
echo "[DONE] Linux build complete."
echo "       Folder : $OUT"
echo "       Zip    : $ZIP"
echo
