#!/bin/sh
set -eu

manifest=${1:-install_manifest.txt}
if [ ! -f "$manifest" ]; then
  printf 'Install manifest not found: %s\n' "$manifest" >&2
  exit 1
fi

while IFS= read -r installed_file || [ -n "$installed_file" ]; do
  case "$installed_file" in
  '') continue ;;
  /*) ;;
  *)
    printf 'Invalid install manifest path: %s\n' "$installed_file" >&2
    exit 1
    ;;
  esac
  rm -f -- "${DESTDIR:-}$installed_file"
done <"$manifest"

# Retain the manifest if any deletion fails, so uninstall can be retried.
rm -f -- "$manifest"
