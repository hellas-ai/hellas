#!/usr/bin/env sh
set -eu
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=x86_64-linux ;;
  Linux-aarch64|Linux-arm64) platform=aarch64-linux ;;
  Darwin-arm64) platform=aarch64-darwin ;;
  *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
archive="hellas-$platform-portable.tar.gz"
base=https://github.com/hellas-ai/hellas/releases/latest/download
directory=${HELLAS_INSTALL_DIR:-"$HOME/.local/bin"}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
curl -fsSL --output-dir "$temporary" --remote-name "$base/$archive" --remote-name "$base/$archive.sha256"
(cd "$temporary"; if command -v sha256sum >/dev/null; then sha256sum -c "$archive.sha256"; else shasum -a 256 -c "$archive.sha256"; fi)
mkdir -p "$directory"
tar -xzf "$temporary/$archive" --strip-components=2 -C "$directory" ./bin/hellas
"$directory/hellas" --version
case ":$PATH:" in *":$directory:"*) ;; *) echo "Add $directory to your PATH" ;; esac
