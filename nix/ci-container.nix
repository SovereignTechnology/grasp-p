{ pkgs, version }:
let
  # The job owns its container daemon: these pinned binaries, not the
  # provider's guest image, decide the Docker, containerd, runc and firewall
  # versions under test. The guest supplies only kernel facilities and root.
  daemonInputs = [
    pkgs.docker
    pkgs.iptables
    pkgs.kmod
    pkgs.gnugrep
    pkgs.coreutils
  ];
in
pkgs.writeShellApplication {
  name = "ngit-grasp-ci-container-deployment";
  runtimeInputs = daemonInputs ++ [
    pkgs.curl
    pkgs.jq
    pkgs.skopeo
  ];
  text = ''
    : "''${NGIT_CI_COMMIT_SHA:?NGIT_CI_COMMIT_SHA is required}"
    : "''${HOME:?HOME is required}"

    fail_requirement() {
      printf 'container job requirement not met: %s\n' "$1" >&2
      printf '%s\n' \
        'This job needs a disposable root environment with cgroup v2 and the' \
        'kernel facilities used by dockerd (overlayfs, bridge, veth, netfilter).' \
        'It must not run on a shared host.' >&2
      exit 2
    }

    [ "$(id -u)" -eq 0 ] || fail_requirement "must run as root"
    if [ ! -e /sys/fs/cgroup/cgroup.controllers ]; then
      fail_requirement "cgroup v2 is not mounted at /sys/fs/cgroup"
    fi
    for facility in overlay bridge veth br_netfilter nf_tables nf_nat; do
      if [ ! -d "/sys/module/$facility" ] && ! modprobe "$facility" 2>/dev/null; then
        fail_requirement "kernel facility $facility is unavailable"
      fi
    done
    grep -qw overlay /proc/filesystems || fail_requirement "overlayfs is unavailable"

    # Everything the daemon writes lives on the job's scratch workspace.
    state="$HOME/container-daemon"
    mkdir -p "$state/data" "$state/exec" "$state/tmp"
    socket="$state/docker.sock"
    log="$state/dockerd.log"
    export DOCKER_HOST="unix://$socket"
    export TMPDIR="$state/tmp"

    dockerd_pid=""
    stop_daemon() {
      status=$?
      if [ -n "$dockerd_pid" ] && kill -0 "$dockerd_pid" 2>/dev/null; then
        kill -TERM "$dockerd_pid"
        for _ in $(seq 1 60); do
          kill -0 "$dockerd_pid" 2>/dev/null || break
          sleep 0.5
        done
        kill -KILL "$dockerd_pid" 2>/dev/null || true
      fi
      if [ "$status" -ne 0 ] && [ -f "$log" ]; then
        echo "--- dockerd log tail ---" >&2
        tail -n 80 "$log" >&2 || true
      fi
      exit "$status"
    }
    trap stop_daemon EXIT
    trap 'exit 130' HUP INT TERM

    started=$(date +%s)
    dockerd \
      --host "$DOCKER_HOST" \
      --data-root "$state/data" \
      --exec-root "$state/exec" \
      --pidfile "$state/dockerd.pid" \
      --storage-driver overlay2 \
      >"$log" 2>&1 &
    dockerd_pid=$!

    deadline=$((started + 60))
    until docker version >/dev/null 2>&1; do
      if ! kill -0 "$dockerd_pid" 2>/dev/null; then
        echo "dockerd exited during startup" >&2
        exit 1
      fi
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "dockerd did not become ready within 60 seconds" >&2
        exit 1
      fi
      sleep 0.5
    done
    ready=$(date +%s)
    docker version --format 'docker client {{.Client.Version}}, daemon {{.Server.Version}}'
    docker info --format 'storage {{.Driver}}, cgroup {{.CgroupVersion}} ({{.CgroupDriver}}), kernel {{.KernelVersion}}'
    echo "dockerd ready after $((ready - started))s"

    RUNNER_TEMP="$state/tmp" \
      scripts/test-container-release.sh "${version}" "$NGIT_CI_COMMIT_SHA"
    finished=$(date +%s)

    summary="container release layout and deployment verified for ${version}
    revision $NGIT_CI_COMMIT_SHA
    daemon startup $((ready - started))s, workload $((finished - ready))s"
    printf '%s\n' "$summary"
    if [ -n "''${NGIT_CI_OUTPUT_DIR:-}" ]; then
      printf '%s\n' "$summary" > "$NGIT_CI_OUTPUT_DIR/summary.txt"
    fi
  '';
}
