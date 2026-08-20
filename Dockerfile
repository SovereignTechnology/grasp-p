# syntax=docker/dockerfile:1

FROM rust:1.96-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

ARG NGIT_BUILD_REVISION=unknown
ENV NGIT_BUILD_REVISION=${NGIT_BUILD_REVISION}

RUN cargo build --locked --release -p ngit-grasp

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gosu \
        libssl3 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ngit-grasp \
    && useradd --system --uid 10001 --gid ngit-grasp \
        --home-dir /data --no-create-home ngit-grasp \
    && install -d -m 0750 -o ngit-grasp -g ngit-grasp \
        /data /data/git /data/relay

COPY --from=builder /src/target/release/ngit-grasp /usr/local/bin/ngit-grasp
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ARG NGIT_IMAGE_VERSION=dev
ARG NGIT_IMAGE_REVISION=unknown
LABEL org.opencontainers.image.title="ngit-grasp" \
      org.opencontainers.image.description="GRASP relay and Git Smart HTTP server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://gitnostr.com/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp.git" \
      org.opencontainers.image.version="${NGIT_IMAGE_VERSION}" \
      org.opencontainers.image.revision="${NGIT_IMAGE_REVISION}"

ENV HOME=/data \
    NGIT_GIT_DATA_PATH=/data/git \
    NGIT_RELAY_DATA_PATH=/data/relay

WORKDIR /data
VOLUME ["/data"]
EXPOSE 7334
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
