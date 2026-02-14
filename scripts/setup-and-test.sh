#!/usr/bin/env bash
# setup-and-test.sh — Build and test gothread from a fresh checkout.
#
# Usage:
#   ./scripts/setup-and-test.sh           # Go tests only
#   ./scripts/setup-and-test.sh --interop # Also build OpenThread and run interop tests
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

INTEROP=false
for arg in "$@"; do
  case "$arg" in
    --interop) INTEROP=true ;;
    --help|-h)
      echo "Usage: $0 [--interop]"
      echo ""
      echo "  --interop  Clone and build OpenThread, then run interop tests"
      echo "             (requires cmake, ninja, and a C/C++ compiler)"
      exit 0
      ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

# ---------- Check prerequisites ----------

echo "==> Checking prerequisites..."

if ! command -v go &>/dev/null; then
  echo "ERROR: Go is not installed. Install Go 1.25+ from https://go.dev/dl/"
  exit 1
fi

GO_VERSION="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1)"
echo "    Go: $(go version)"

if [ "$INTEROP" = true ]; then
  for tool in cmake git; do
    if ! command -v "$tool" &>/dev/null; then
      echo "ERROR: $tool is required for --interop but not found."
      exit 1
    fi
  done
  echo "    CMake: $(cmake --version | head -1)"
fi

# ---------- Build ----------

echo ""
echo "==> Building all packages..."
go build ./...
echo "    ✓ Build succeeded"

# ---------- Go tests ----------

echo ""
echo "==> Running tests (98 packages)..."
if go test ./... -count=1; then
  echo "    ✓ All tests passed"
else
  echo "    ✗ Some tests failed"
  exit 1
fi

# ---------- Interop (optional) ----------

if [ "$INTEROP" = false ]; then
  echo ""
  echo "Done. To also run OpenThread interop tests:"
  echo "  $0 --interop"
  exit 0
fi

echo ""
echo "==> Setting up OpenThread interop..."

OT_DIR="$REPO_ROOT/openthread"
OT_BIN="$OT_DIR/build/simulation/examples/apps/cli/ot-cli-ftd"

if [ ! -f "$OT_BIN" ]; then
  # Clone if not present
  if [ ! -d "$OT_DIR" ]; then
    echo "    Cloning openthread..."
    git clone --depth 1 https://github.com/openthread/openthread.git "$OT_DIR"
  fi

  # Build
  echo "    Building ot-cli-ftd (this may take a few minutes)..."
  cd "$OT_DIR"

  CMAKE_EXTRA_ARGS=""
  # macOS ARM64 needs -DOT_TCP=OFF to avoid mbedTLS linker issues
  if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
    CMAKE_EXTRA_ARGS="-DOT_TCP=OFF"
    echo "    (macOS ARM64 detected — building with -DOT_TCP=OFF)"
  fi

  OT_CMAKE_NINJA_TARGET="ot-cli-ftd" \
    OT_CMAKE_BUILD_SHARED_LIBS=OFF \
    script/cmake-build simulation $CMAKE_EXTRA_ARGS

  cd "$REPO_ROOT"
fi

if [ ! -f "$OT_BIN" ]; then
  echo "ERROR: ot-cli-ftd binary not found after build."
  echo "       Expected at: $OT_BIN"
  exit 1
fi

echo "    ✓ ot-cli-ftd ready: $OT_BIN"

echo ""
echo "==> Running interop test (takes ~40s for OT leader election)..."
if go test -v ./platform/simulation/... -run TestInteropReceiveOTFrame -timeout 120s; then
  echo "    ✓ Interop test passed"
else
  echo "    ✗ Interop test failed"
  exit 1
fi

echo ""
echo "Done. All tests including OpenThread interop passed."
