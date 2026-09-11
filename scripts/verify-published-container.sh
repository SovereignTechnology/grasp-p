#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi

version=$1
case "${version}" in
    [A-Za-z0-9_]*) ;;
    *)
        echo "version is not a valid OCI tag: ${version}" >&2
        exit 2
        ;;
esac
case "${version}" in
    *[!A-Za-z0-9._-]*)
        echo "version is not a valid OCI tag: ${version}" >&2
        exit 2
        ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "missing required command: docker" >&2
    exit 2
fi

image="ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:${version}"
cleanup() {
    docker image rm --force "${image}" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

deadline=$(($(date +%s) + 300))
until docker pull "${image}"; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        echo "published image did not become pullable within five minutes" >&2
        exit 1
    fi
    sleep 5
done

actual=$(docker run --rm --entrypoint /usr/local/bin/ngit-grasp \
    "${image}" --version)
expected="ngit-grasp ${version}"
if [ "${actual}" != "${expected}" ]; then
    echo "expected '${expected}' from the published image, got '${actual}'" >&2
    exit 1
fi

printf 'published image verified: %s\n' "${image}"
