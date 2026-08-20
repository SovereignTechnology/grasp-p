# Deploy on managed hosting

The supplied container can run on Railway, Render, and Fly.io when each service
has a custom domain, one persistent `/data` volume, and exactly one running
instance. These platforms terminate TLS and proxy WebSockets to ngit-grasp.

Managed hosting is best for a small or moderate relay whose operator accepts
brief upgrade downtime. For a large existing relay, use NixOS, systemd, or
Compose so startup migrations and storage snapshots remain under direct
operator control.

Read the [deployment contract](../reference/deployment-contract.md) first. In
particular, provider replicas do not make ngit-grasp highly available: their
local volumes do not replicate application state.

## Common requirements

For every provider:

- set `NGIT_DOMAIN` to the final custom hostname, not the provider hostname;
- mount durable storage at `/data` before the first successful start;
- keep the instance count at one and disable scale-to-zero;
- keep `NGIT_BASE_PATH=/` unless path routing has been designed explicitly;
- allow at least five minutes between `SIGTERM` and forced termination; and
- take an external backup of `/data`, including `.relay-owner.nsec`.

The image maps a platform-provided `PORT` to `0.0.0.0:${PORT}`. Do not set
`NGIT_BIND_ADDRESS` unless the provider template below does so explicitly.

## Railway

`railway.toml` selects the Dockerfile, uses `/` as the health check, disables
old/new deployment overlap, and gives shutdown five minutes. Railway storage is
configured separately from config-as-code. See Railway's
[config-as-code reference](https://docs.railway.com/config-as-code/reference)
and [volume guide](https://docs.railway.com/volumes) for the provider-side
details.

From the repository root with the Railway CLI installed:

```bash
railway login
railway init
railway add --service ngit-grasp
railway service ngit-grasp
railway variable set NGIT_DOMAIN=ngit.example.com NGIT_BASE_PATH=/
railway volume add --mount-path /data
railway up
railway domain ngit.example.com
```

Add the DNS records returned by `railway domain`, then inspect status and verify
the public relay:

```bash
railway domain status ngit.example.com
railway deployment list --json
scripts/verify-deployment.sh https://ngit.example.com
```

Do not add replicas or multi-region configuration. Railway mounts a new volume
as root; the image entrypoint prepares it and drops privileges before starting
ngit-grasp.

Railway volume backups are useful recovery points, but also export or snapshot
state outside the platform. During a large storage migration, increase the
health-check timeout or move the upgrade to a directly operated host.

## Render

`render.yaml` describes a paid `starter` web service with a 10 GB disk mounted
at `/data`, a root health check, a five-minute shutdown delay, and automatic
deploys disabled. Render prompts for `NGIT_DOMAIN` when the Blueprint is
created. The fields follow Render's
[Blueprint specification](https://render.com/docs/blueprint-spec); its
[persistent disk guide](https://render.com/docs/disks) describes the storage
and scaling constraints.

Render Blueprints require a repository connected through one of Render's
supported Git providers. Until ngit-grasp has an authorized mirror or published
OCI image, use Render's **Public Git Repository** flow with the canonical URL:

```text
https://gitnostr.com/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp.git
```

Choose Docker and apply the values from `render.yaml` in the service form:

- environment variable `NGIT_DOMAIN=ngit.example.com`;
- persistent disk mounted at `/data`;
- health check path `/`;
- maximum shutdown delay 300 seconds; and
- one instance with automatic deploys disabled.

Add and verify the custom domain before publishing it in repository
announcements. Render services backed by a persistent disk cannot run multiple
instances and have brief downtime during deploys, which matches the relay's
single-writer requirement.

After a manual deploy, run:

```bash
scripts/verify-deployment.sh https://ngit.example.com
```

Use Render disk snapshots plus an independent backup. Only `/data` persists;
all other container filesystem changes are ephemeral.

## Fly.io

Fly volumes are local to one Machine and are not automatically replicated. The
template therefore disables autostop, uses an immediate replacement strategy,
and must be deployed with high-availability seeding disabled. See Fly's
[configuration reference](https://fly.io/docs/reference/configuration/) and
[volume overview](https://fly.io/docs/volumes/overview/) for the underlying
platform behavior.

Copy and edit the template:

```bash
cp fly.toml.example fly.toml
# Set a unique app name, primary region, and NGIT_DOMAIN in fly.toml.
fly config validate --strict --config fly.toml
```

Create the app and one volume in the same region, then deploy one Machine:

```bash
fly apps create replace-with-a-unique-ngit-grasp-name
fly volumes create ngit_grasp_data --region ord --size 10
fly deploy --ha=false
fly scale count 1
fly certs add ngit.example.com
```

Use the app name and region selected in `fly.toml`, add the DNS records shown by
`fly certs`, then verify:

```bash
fly checks list
fly scale show
scripts/verify-deployment.sh https://ngit.example.com
```

Never scale above one: Fly creates a separate empty volume for each additional
Machine and does not copy ngit-grasp state. A single Machine and volume can be
unavailable after host failure, so maintain an external backup rather than
relying only on Fly snapshots.

## Upgrades

Managed volume deployments cannot provide a safe zero-downtime writer handoff.
Expect brief downtime:

1. disable automatic deploys;
2. take a complete provider snapshot and an external backup;
3. deploy the pinned revision with one instance;
4. inspect startup and integrity logs; and
5. run the public verifier.

For a storage-changing release, restore both the prior executable and its
matching pre-upgrade `/data` snapshot when rolling back.
