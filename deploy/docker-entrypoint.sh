#!/bin/sh
set -eu

data_root=/data
git_data_path=${NGIT_GIT_DATA_PATH:-${data_root}/git}
relay_data_path=${NGIT_RELAY_DATA_PATH:-${data_root}/relay}

if [ -z "${NGIT_BIND_ADDRESS:-}" ]; then
    public_port=${PORT:-7334}
    case "${public_port}" in
        ''|*[!0-9]*)
            echo "PORT must be an integer" >&2
            exit 2
            ;;
    esac
    if [ "${public_port}" -lt 1 ] || [ "${public_port}" -gt 65535 ]; then
        echo "PORT must be between 1 and 65535" >&2
        exit 2
    fi
    export NGIT_BIND_ADDRESS="0.0.0.0:${public_port}"
fi

export NGIT_GIT_DATA_PATH="${git_data_path}"
export NGIT_RELAY_DATA_PATH="${relay_data_path}"

if [ "$(id -u)" -eq 0 ]; then
    install -d -m 0750 -o ngit-grasp -g ngit-grasp \
        "${data_root}" "${git_data_path}" "${relay_data_path}"

    if [ -e "${data_root}/.relay-owner.nsec" ]; then
        chown ngit-grasp:ngit-grasp "${data_root}/.relay-owner.nsec"
        chmod 0600 "${data_root}/.relay-owner.nsec"
    fi

    exec gosu ngit-grasp:ngit-grasp ngit-grasp "$@"
fi

exec ngit-grasp "$@"
