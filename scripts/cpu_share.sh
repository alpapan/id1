#!/usr/bin/env bash
#
# group: test-tooling
# tags: parallelism, workers, cpus
# summary: How many processors one test, lint or build run may use on THIS machine.
#
# Prints one integer on stdout, or halts with a message on stderr and a non-zero
# exit. A processor count nobody could read is a halt, not a fallback: a share
# derived from an input that was not supplied is a number that looks authoritative
# and is not.
#
# The share is a quarter of the host's processors, never fewer than FLOOR, never
# more than CAP, and never more than the processors themselves. It is the one
# definition every parallelism setting in the monorepo takes (pytest-xdist `-n`,
# pyright `--threads`, Vitest and Jest worker counts, `go test -p`, `xargs -P`,
# `make -j`), so a host is never handed to one run whole. The floor is the part
# that exceeds a quarter on a small host (4 of 10 processors is 40%); the cap is
# what bounds a very large one (62 processors give 15).
#
# This file is copied byte-for-byte into every repository that has a task needing
# it, because each repository runs its own tasks from its own checkout. The copies
# are pinned identical by tests/unit/test_parallelism_is_a_share.py in the
# assistant project; edit them all together.

set -euo pipefail

DIVISOR=4
FLOOR=4
CAP=18

# `nproc` honours OMP_NUM_THREADS and OMP_THREAD_LIMIT, so a caller's own thread cap
# would read as a smaller host; the processors this process may run on are what count.
if ! cpus="$(env -u OMP_NUM_THREADS -u OMP_THREAD_LIMIT nproc 2>/dev/null)"; then
    echo "cpu_share.sh: nproc failed, so the host's processor count is unknown. A share cannot be derived from it." >&2
    exit 69
fi

if ! printf '%s' "${cpus}" | grep -qE '^[0-9]+$' || [ "${cpus}" -lt 1 ]; then
    echo "cpu_share.sh: nproc printed '${cpus}', which is not a positive whole number of processors." >&2
    exit 69
fi

share=$(( cpus / DIVISOR ))
if [ "${share}" -gt "${CAP}" ]; then
    share="${CAP}"
fi
if [ "${share}" -lt "${FLOOR}" ]; then
    share="${FLOOR}"
fi
if [ "${share}" -gt "${cpus}" ]; then
    share="${cpus}"
fi

printf '%s\n' "${share}"
