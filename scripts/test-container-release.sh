#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <version> <40-character-git-revision>" >&2
    exit 2
fi

version=$1
revision=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

case "${revision}" in
    *[!0-9a-f]*)
        echo "revision is not a lowercase hexadecimal Git object ID: ${revision}" >&2
        exit 2
        ;;
esac
if [ "${#revision}" -ne 40 ]; then
    echo "revision is not a 40-character Git object ID: ${revision}" >&2
    exit 2
fi

for required_command in docker jq skopeo; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 2
    fi
done

temporary_parent=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temporary_parent=${temporary_parent%/}
case "${temporary_parent}" in
    /*) ;;
    *)
        echo "temporary directory parent must be absolute: ${temporary_parent}" >&2
        exit 2
        ;;
esac
if [ ! -d "${temporary_parent}" ]; then
    echo "temporary directory parent does not exist: ${temporary_parent}" >&2
    exit 2
fi
test_directory=$(mktemp -d "${temporary_parent}/ngit-grasp-container-release-test.XXXXXX")
case "${test_directory}" in
    "${temporary_parent}"/ngit-grasp-container-release-test.??????) ;;
    *)
        echo "refusing to use unexpected test directory: ${test_directory}" >&2
        exit 2
        ;;
esac

layout=${test_directory}/layout
image_name=ngit-grasp:release-test-${revision}-$$
case "${image_name}" in
    ngit-grasp:release-test-[0-9a-f]*-[0-9]*) ;;
    *)
        echo "refusing to use unexpected test image name" >&2
        exit 2
        ;;
esac

cleanup() {
    docker image rm --force "${image_name}" >/dev/null 2>&1 || true
    rm -rf -- "${test_directory}"
}
trap cleanup EXIT HUP INT TERM

"${script_dir}/build-container-layout.sh" \
    "${version}" \
    "${revision}" \
    "${layout}"

skopeo --insecure-policy copy --format v2s2 \
    "oci:${layout}:${version}" \
    "docker-daemon:${image_name}"

NGIT_TEST_IMAGE=${image_name} \
    "${script_dir}/test-container-deployment.sh"

printf 'OCI release layout and imported image verified for %s\n' "${version}"
