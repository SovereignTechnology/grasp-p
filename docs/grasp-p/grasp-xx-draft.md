# GRASP-XX Operator-untrusted Private Repositories

Status: DRAFT - expect breaking changes.

Purpose: to host many independent private repositories on a public service that stores only ciphertext and opaque public keys, that can later become public.

This is an optional extension to GRASP-01.

## Relationship to GRASP-08

GRASP-08 and GRASP-XX are alternative trust models and compose freely; neither replaces the other. GRASP-08 trusts the operator: a service-wide whitelist, [NIP-42](https://nips.nostr.com/42) read-gating and uniform `401` responses hide a repository's existence, and the service holds plaintext git data. GRASP-XX trusts the operator with nothing: tenancy is per repository rather than service-wide, the service never holds plaintext, and confidentiality never depends on read-gating. A GRASP-08 read-gate in front of a GRASP-XX tenancy is defence in depth — existence-hiding over ciphertext-only storage.

Client key derivation, encryption, membership, invites and key rotation are out of scope: the service cannot observe them. They are described informatively in the companion CORD-git specification, as GRASP-08 defers token mechanics to the Nostr Web Token NIP.

## Repository Registration

A tenant claims an opaque repository slot with an addressable kind `30640` event signed by the hosting pubkey.

MUST reject a registration whose `d` tag is not exactly 32 lowercase hex characters. The `d` tag is an alias and MUST NOT be derived from the repository name.

`w` tags register write keys and `aux` tags register auxiliary keys, as `["w", <pubkey-hex>, <pop-sig-hex>]`. MUST require at least one `w` tag. MUST reject a key appearing more than once across `w` and `aux`. MAY cap the combined count (reference default 64).

MUST verify, for every registered key other than the event author, a proof of possession in the tag's third value: a 128-hex BIP-340 schnorr signature by that key over `SHA256("grasp-p key-claim:" || <tenant-hex> || ":" || <alias>)`, where `<tenant-hex>` is the author's x-only pubkey. The author key is exempt; the event signature is its proof. This binds a claim to one tenant and alias and prevents key-namespace squatting.

MUST reject a registration unless its `relays` tags and its `server` tags each contain a value denoting this service's own host. Matching MUST be on the exact host, not a substring.

```yaml
{
  "kind": 30640,
  "tags": [
    ["d", "9f2c1ab4d7e05386b1c4f9a70d2e6b83"],
    ["w", "<write-pubkey-hex>", "<128-hex-pop-sig>"],
    ["aux", "<aux-pubkey-hex>", "<128-hex-pop-sig>"],
    ["relays", "wss://<host>"],
    ["server", "https://<host>"]
  ],
  "content": ""
}
```

### Conflict resolution

When an incoming registration claims an alias held by another tenant, or a key claimed under another alias, MUST resolve deterministically: the lowest `created_at` wins, ties break to the lowest event id. Both operands MUST be compared against the holder's **first** registration edition, never its latest and never a node-local timestamp, so that partitioned services converge on the same winner. A same-tenant replacement preserves the anchor; authentic older same-tenant evidence lowers it.

MUST NOT let node-local state gate a merge winner. A winner is exempt from alias-count limits, the quota check and the replacement-cadence limit. Admission-mode gates do apply, because paired services are required to run identical, fingerprint-verified admission config.

MUST free a losing or deleted registration's key claims, alias slot and blob claims. Claims MUST also be freed by an author-valid [NIP-09](https://nips.nostr.com/9) kind `5` deletion and by a [NIP-62](https://nips.nostr.com/62) vanish targeting this service, both honouring a `created_at` cutoff so a replayed stale deletion cannot free a newer edition. MAY rate-limit same-tenant replacements (reference default: burst 8, refill 4/hour). A replacement rejected for cadence MUST be held and re-offered by the sync layer after refill; convergence MUST NOT depend on the client retrying.

## Repository State

An addressable kind `30641` event carries the encrypted state root.

MUST reject a state root not signed by a `w` key of the live registration; `aux` keys MUST NOT publish state roots. MUST reject one whose `d` tag is not the alias, or whose `a` tag is not `30640:<tenant-hex>:<alias>` matching that live registration.

MUST accept exactly one `m` tag `["m", <sha256>, <bytes>]` naming the manifest blob, and any number of `pack` tags of the same shape. MAY cap the total (reference default 256 references per edition).

SHOULD retain the last N editions per **alias** (reference default 16), shared across every write key of that alias. This ring is distinct from NIP-01 addressable replacement, which remains per `(author, alias)`. Two writers on one alias therefore share one ring and halve each other's retained history.

MUST reject any event of the kinds in this document whose `created_at` is more than 900 seconds in the future, so a future-dated edition cannot evict the live one by addressable replacement.

## Encrypted Streams

Kind `3359` carries stored encrypted stream traffic and kind `23359` is its ephemeral analog.

MUST admit these kinds only when the signer is in the `w ∪ aux` set of a live registration **and** the event passes the size, skew, quota and rate gates. Membership is necessary, not sufficient. MUST NOT inspect their content. MUST reject an event of these kinds signed by a key in no live registration, rather than falling through to the GRASP-01 related-event path; otherwise every deregistered address is permanently floodable and chargeable to nobody. A rejected stored wrap SHOULD be held, keyed by its signer, and reprocessed if a later registration registers that key. An ephemeral wrap MUST NOT be stored or held.

### Why not kind `1059`

These events are NIP-59-*shaped* but are not [NIP-59](https://nips.nostr.com/59) gift wraps: they carry no `p` tag, no kind `13` seal, their content is a symmetric AEAD envelope rather than [NIP-44](https://nips.nostr.com/44), and the signer is deterministically derived and shared by the group rather than a one-time random key. Their inner events are signed, where NIP-59 rumors are by definition unsigned — so conformance is not merely inconvenient here, it is unreachable. Reusing kind `1059` would oblige relays to apply NIP-59's relay behaviours to them — AUTH-gating, and serving only to the p-tagged recipient — under which a p-tag-less wrap is servable to nobody, and one conformant relay upgrade can black-hole a repository. It would also demand two contradictory treatments of one kind wherever GRASP-08 and GRASP-XX share a relay. Kinds `3359` and `23359` are unclaimed in the NIP corpus; assignment is requested. (A service migrating clients off a prior `1059`-based deployment MAY dual-accept the old kinds behind a flag for a transitional window — the reference service does, defaulting on — but that window is a deployment concern, not part of this specification.)

## Blob Store

MUST serve the [Blossom](https://github.com/hzrd149/blossom) subset BUD-01, BUD-02 and BUD-06: `GET /<sha256>`, `PUT /upload`, `HEAD /upload`. `DELETE /<sha256>` and `GET /list/<pubkey>` are BUD-12, which marks `/list` unrecommended.

Authorization is BUD-11 kind `24242`. MUST verify the event's id and signature, that its `t` tag matches the operation, that its `expiration` ([NIP-40](https://nips.nostr.com/40)) is present, numeric and in the future, and that its `x` tag equals the sha256 being operated on. MUST require an `a` tag of `30640:<tenant-hex>:<alias>` and MUST reject unless the signer is in that registration's `w` set — a GRASP-XX extension to BUD-11 that makes the upload attributable to one tenancy.

```text
Authorization: Nostr <base64url-no-padding-event>
```

> Implementation status: the reference service decodes standard base64 only, and does not yet enforce BUD-11's `server` tag or its human-readable `content` requirement; alignment is in progress.

`GET /<sha256>` and `GET /list/<pubkey>` are UNAUTHENTICATED. Any anonymous party can therefore enumerate the complete alias-to-blob mapping of a hosting pubkey in one request — hashes, sizes, counts and by extension push cadence — rather than having to observe pushes as they happen. Blob content stays encrypted. This is a trade, and an implementation is free to take the other side of it: one wanting the weaker leak MUST either require a `24242` authorization on `/list` or not serve the route at all. The reference service takes the leak.

## NIP-11

SHOULD advertise a top-level `private_repos` object, which [NIP-11](https://nips.nostr.com/11) permits because clients MUST ignore fields they do not understand. It MUST carry at least `kinds` (eg. `[30640, 30641, 3359, 23359]`) and a `policy_fingerprint` — a digest over the admission-affecting configuration, so paired services can be checked for admission parity. The reference service also publishes `policy_version`, `registration_mode`, size caps, quotas and `blob_endpoints`. The `kinds` array is the discovery signal for this extension and MUST track the kinds actually admitted.

## Rejection Messages

MUST use these [NIP-20](https://nips.nostr.com/20) `restricted: ` messages, which clients rely on to tell a re-registerable condition from a transient one.

| Condition | Message |
|---|---|
| kind `30641`, no live registration for the alias | `unregistered alias` |
| stream wrap, signer unclaimed or alias not live | `unregistered key` |
| kind `30641`, registration identity changed mid-transaction | `alias registration changed; retry` |
| stream wrap, registration identity changed mid-transaction | `registration changed; retry` |
| kind `30640`, same-tenant replacement over cadence | `replacement rate-limited; retry later` |
| client write bucket exhausted | `rate-limited; retry later` |
| kind `30640` lost an alias conflict | `alias already registered` |
| kind `30640` lost a key conflict | `write key already registered` |
| `created_at` beyond the future skew | `event created_at is too far in the future` |

A client MUST treat any message containing the substring `unregistered` as re-registerable, and `registration changed; retry` as transient. The two transient messages therefore MUST NOT contain that substring.

## Discovery

Clients SHOULD discover a user's private repositories through GRASP-08's encrypted kind `10318` private git relay list, used unchanged.

A repository MAY additionally publish a kind `30617` announcement carrying GRASP-08's `["private", "true"]` tag, a `d` tag equal to the alias and a `nostr://` clone URL, and NO `name` or `description`, so that clients treat both trust models uniformly. This is opt-in per repository and MUST NOT be a default: it converts "an opaque alias exists" into "this coordinate exists, is private, and has these maintainers", and creates a stable public coordinate correlatable across relays and over time.

> Implementation status: this section is specified but unbuilt — the reference client implements neither the kind `10318` list nor the `30617` announcement, so a repository hosted on it is today discoverable only out of band.

## Becoming Public

A repository becomes public by decrypting locally and republishing as standard [NIP-34](https://nips.nostr.com/34) — a kind `30617` announcement without the `private` tag, plus kind `30618` state — on the same service, then issuing a NIP-09 kind `5` deletion for its kind `30640` and kind `30641` events.

## Caveats

The service verifies signatures against opaque keys and moves bytes; it cannot read repository names, refs, contributor identities or file contents. It does learn, and MUST be assumed to publish: the hosting pubkey, the alias, the registered keys, blob hashes, sizes and timing, and epoch lineage across rotations. The relay stays public-read, so ciphertext harvest by any anonymous party is conceded, not prevented — an adversary who later obtains a key can decrypt what they stored. Confidentiality rests on client-side encryption alone; a member who has been removed keeps every ciphertext and key they already held.
