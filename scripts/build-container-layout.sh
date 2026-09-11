#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <version> <40-character-git-revision> [layout]" >&2
    exit 2
fi

version=$1
revision=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
container_context=${CONTAINER_CONTEXT:-${repository_root}}
container_context=$(CDPATH='' cd -- "${container_context}" && pwd)
exact_only=${CONTAINER_EXACT_ONLY:-false}

case "${exact_only}" in
    true | false) ;;
    *)
        echo "CONTAINER_EXACT_ONLY must be true or false" >&2
        exit 2
        ;;
esac

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
if [ "${#version}" -gt 128 ]; then
    echo "version is longer than the OCI tag limit: ${version}" >&2
    exit 2
fi
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

layout=${3:-artifacts/ngit-grasp}
case "${layout}" in
    "")
        echo "layout path must not be empty" >&2
        exit 2
        ;;
    /*) ;;
    *) layout=${container_context}/${layout} ;;
esac
if [ -e "${layout}" ]; then
    echo "refusing to replace existing OCI layout: ${layout}" >&2
    exit 2
fi

for required_command in docker du jq skopeo; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 2
    fi
done

image_name=ngit-grasp-release-layout:${revision}-$$
case "${image_name}" in
    ngit-grasp-release-layout:[0-9a-f]*-[0-9]*) ;;
    *)
        echo "refusing to use unexpected temporary image name" >&2
        exit 2
        ;;
esac

remove_image=false
cleanup() {
    if [ "${remove_image}" = true ]; then
        docker image rm --force "${image_name}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

docker build \
    --pull \
    --platform linux/amd64 \
    --build-arg "NGIT_BUILD_REVISION=${revision}" \
    --build-arg "NGIT_IMAGE_REVISION=${revision}" \
    --build-arg "NGIT_IMAGE_VERSION=${version}" \
    --tag "${image_name}" \
    "${container_context}"
remove_image=true

mkdir -p "$(dirname -- "${layout}")"
skopeo --insecure-policy copy --format oci \
    "docker-daemon:${image_name}" \
    "oci:${layout}:${version}"

if [ "${exact_only}" = true ]; then
    alias_tag=${version}
else
    case "${version}" in
        *-*)
            prerelease=${version#*-}
            alias_tag=${prerelease%%[.+]*}
            ;;
        *) alias_tag=latest ;;
    esac
fi
case "${alias_tag}" in
    [A-Za-z0-9_]*) ;;
    *)
        echo "derived channel is not a valid OCI tag: ${alias_tag}" >&2
        exit 2
        ;;
esac
case "${alias_tag}" in
    *[!A-Za-z0-9_.-]*)
        echo "derived channel is not a valid OCI tag: ${alias_tag}" >&2
        exit 2
        ;;
esac

index=${layout}/index.json
temporary_index=${index}.tmp.$$
jq --arg version "${version}" --arg alias "${alias_tag}" '
    if .schemaVersion != 2 then
        error("OCI layout index schemaVersion must be 2")
    elif (.manifests | length) != 1 then
        error("OCI exporter must produce exactly one root manifest")
    else
        .manifests[0] as $image
        | .manifests = (
            [($image | .annotations = ((.annotations // {}) + {
                "org.opencontainers.image.ref.name": $version
            }))]
            + if $alias == $version then [] else [
                ($image | .annotations = ((.annotations // {}) + {
                    "org.opencontainers.image.ref.name": $alias
                }))
            ] end
        )
    end
' "${index}" > "${temporary_index}"
mv "${temporary_index}" "${index}"

jq -e --arg version "${version}" --arg alias "${alias_tag}" '
    [.manifests[].annotations["org.opencontainers.image.ref.name"]]
    == (if $version == $alias then [$version] else [$version, $alias] end)
' "${index}" >/dev/null

layout_measure=$(du --apparent-size --block-size=1 --summarize -- "${layout}")
layout_bytes=${layout_measure%%[!0-9]*}
case "${layout_bytes}" in
    '' | *[!0-9]*)
        echo "failed to measure OCI layout: ${layout_measure}" >&2
        exit 1
        ;;
esac

if [ "${version}" = "${alias_tag}" ]; then
    printf 'OCI layout ready at %s with tag %s (%s apparent bytes)\n' \
        "${layout}" "${version}" "${layout_bytes}"
else
    printf 'OCI layout ready at %s with tags %s and %s (%s apparent bytes)\n' \
        "${layout}" "${version}" "${alias_tag}" "${layout_bytes}"
fi
