#!/bin/bash
# The single source of this repository's Python bytecode-cache path.
#
# CPython writes __pycache__ directories and .pyc files beside the source it imports. A
# checkout SHARED between accounts therefore collects, inside one account's tree, bytecode
# owned by whichever account imported each module first. No single command is the cause:
# every import from inside the checkout writes bytecode beside the source. The criterion is
# that the checkout is shared, never what storage carries it.
#
# $HOME is the destination precisely because it is per-account and not shared. Two accounts
# writing one cache directory would collide.
#
# Pixi sources this script before it applies each manifest's activation table, and every pixi
# manifest in this repository expands the variable exported below. Change the path here; the
# manifests carry a pointer to this file and never the path itself.
if [ -z "${HOME:-}" ]; then
  echo "REFUSING: HOME must be set for the pycache redirect" >&2
  exit 1
fi
export CURATORIUM_PYCACHE_PREFIX="$HOME/.cache/curatorium-pycache"
