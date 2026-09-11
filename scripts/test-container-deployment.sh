#!/bin/sh
set -eu

container_engine=${CONTAINER_ENGINE:-docker}
test_suffix=$$
container_name=ngit-grasp-deployment-test-${test_suffix}
volume_name=ngit-grasp-deployment-test-${test_suffix}
if [ -n "${NGIT_TEST_IMAGE:-}" ]; then
    image_name=${NGIT_TEST_IMAGE}
    build_test_image=false
    remove_test_image=false
else
    image_name=ngit-grasp:deployment-test-${test_suffix}
    build_test_image=true
    remove_test_image=true
fi

case "${container_name}" in
    ngit-grasp-deployment-test-[0-9]*) ;;
    *)
        echo "refusing to use unexpected test resource name" >&2
        exit 2
        ;;
esac

if ! command -v "${container_engine}" >/dev/null 2>&1; then
    echo "missing container engine: ${container_engine}" >&2
    exit 2
fi
for required_command in curl jq; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 2
    fi
done

cleanup() {
    "${container_engine}" rm --force "${container_name}" >/dev/null 2>&1 || true
    "${container_engine}" volume rm "${volume_name}" >/dev/null 2>&1 || true
    if [ "${remove_test_image}" = true ]; then
        "${container_engine}" image rm "${image_name}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

start_container() {
    "${container_engine}" run \
        --detach \
        --name "${container_name}" \
        --publish 127.0.0.1::7334 \
        --volume "${volume_name}:/data" \
        --env NGIT_DOMAIN=localhost \
        "${image_name}" >/dev/null
}

relay_url() {
    published_port=$("${container_engine}" port "${container_name}" 7334/tcp)
    published_port=${published_port##*:}
    printf 'http://127.0.0.1:%s' "${published_port}"
}

relay_pubkey() {
    curl \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 5 \
        --max-time 15 \
        --retry 30 \
        --retry-all-errors \
        --retry-max-time 180 \
        --header 'Accept: application/nostr+json' \
        "$1" | jq -er '.pubkey'
}

if [ "${build_test_image}" = true ]; then
    "${container_engine}" build --tag "${image_name}" .
fi
"${container_engine}" volume create "${volume_name}" >/dev/null

start_container
first_url=$(relay_url)
first_pubkey=$(relay_pubkey "${first_url}")
"${container_engine}" exec "${container_name}" \
    test -s /data/.relay-owner.nsec

"${container_engine}" stop --time 300 "${container_name}" >/dev/null
"${container_engine}" rm "${container_name}" >/dev/null

start_container
second_url=$(relay_url)
second_pubkey=$(relay_pubkey "${second_url}")

if [ "${first_pubkey}" != "${second_pubkey}" ]; then
    echo "relay identity changed after container replacement" >&2
    exit 1
fi

echo "container deployment verified; relay identity persisted"
