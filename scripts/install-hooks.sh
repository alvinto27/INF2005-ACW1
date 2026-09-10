#!/usr/bin/env sh
# Configure this repository's documented pre-commit hook without replacing another hook path.
set -eu

root=$(git rev-parse --show-toplevel)
expected="$root/.githooks"
current=$(git config --local --get core.hooksPath || true)

case "$current" in
    ""|.githooks|"$expected")
        git config --local core.hooksPath "$expected"
        printf 'Configured core.hooksPath=%s\n' "$expected"
        ;;
    *)
        printf 'Refusing to replace existing local core.hooksPath: %s\n' "$current" >&2
        printf 'Review that configuration, then set it to %s manually if intended.\n' "$expected" >&2
        exit 1
        ;;
esac
