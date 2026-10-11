# GRASP-XX Operator-untrusted Private Repositories

Status: DRAFT - expect breaking changes.

Purpose: to host many independent private repositories on a public service that stores only ciphertext and opaque public keys, and that can later become public. The operator is trusted with no plaintext. This is an optional extension to GRASP-01. GRASP-08 also addresses private repositories, under a trusted-operator model; the two are independent.

Client key derivation, encryption, membership, invites and key rotation are out of scope: the service cannot observe them. They are described informatively in the companion CORD-git specification. Discovery is also out of scope — a repository is addressed by its hosting pubkey and alias, the `nostr://<hosting-npub>/<alias>` coordinate, obtained out of band. Kinds `30640`, `30641`, `3359` and `23359` are as specified here; all four are unclaimed in the [NIPs](https://github.com/nostr-protocol/nips) corpus as of 2026-07-28, and adding them to the NIP kind index is a separate submission.

## Repository Registration

A tenant claims an opaque repository slot with an addressable kind `30640` event signed by the hosting pubkey. MUST reject a registration whose `d` tag is not exactly 32 lowercase hex characters. The `d` tag is an alias and MUST NOT be derived from the repository name.

`w` tags register write keys and `aux` tags register auxiliary keys, each as `["w", <pubkey-hex>, <pop-sig-hex>]` with a 64 lowercase hex pubkey. MUST require at least one `w` tag. MUST reject a key appearing more than once across `w` and `aux`. MAY cap the combined count (reference default 64). An `aux` key MUST NOT publish kind `30641` events or blobs.

MUST verify a proof of possession for every registered key other than the event author: the tag's third value MUST be a 128 lowercase hex BIP-340 signature by that key over the 32-byte SHA-256 digest of the US-ASCII string `grasp-p key-claim:<tenant-hex>:<alias>`, where `<tenant-hex>` is the author's 64 lowercase hex x-only pubkey and `<alias>` is the `d` value. That digest is the BIP-340 message, over which BIP-340 applies its own tagged hash. `grasp-p key-claim:` is a permanent opaque constant and MUST NOT be parameterised on the GRASP number. For the author's own key the third value is OPTIONAL and MUST be ignored; the event signature is its proof.

MUST reject a registration unless its `relays` tags and its `server` tags each contain a value denoting this service's own host and its mount path, if any. Matching MUST be on the exact host, not a substring; for a service mounted under a path the value's path, with trailing slashes removed, MUST equal that path, so that the bare host, or another path on it, does not denote the service. `relays` names this service's relay and `server` its blob store, in place of GRASP-01's `clone`.

When an incoming registration claims an alias held by another tenant, or a key claimed under another alias, MUST resolve deterministically: the lowest `created_at` wins, ties break to the lowest event id. Both operands MUST be compared against the holder's **first** registration edition, never its latest and never a node-local timestamp. A same-tenant replacement preserves that anchor; authentic older same-tenant evidence lowers it. MUST NOT let node-local counters gate a winner: a winner is exempt from alias-count limits, the quota check and the replacement-cadence limit. Admission-mode gates such as whitelist and proof of work do apply.

MUST free a losing or deleted registration's key claims, alias slot and blob claims. Claims MUST also be freed by an author-valid [NIP-09](https://nips.nostr.com/9) kind `5` deletion and by a [NIP-62](https://nips.nostr.com/62) vanish targeting this service, both honouring a `created_at` cutoff so a replayed stale deletion cannot free a newer edition. MAY rate-limit same-tenant replacements (reference default: burst 8, refill 4/hour).

## Repository State

An addressable kind `30641` event carries the encrypted state root. MUST reject a state root not signed by a `w` key of the live registration. MUST reject one whose `d` tag is not the alias, or whose `a` tag is not `30640:<tenant-hex>:<alias>` matching that live registration. MUST accept exactly one `m` tag `["m", <sha256>, <bytes>]` naming the manifest blob, and any number of `pack` tags of the same shape. MAY cap the total (reference default 256 references per edition). SHOULD retain the last N editions per **alias** (reference default 16), shared across every write key of that alias, for blob-claim accounting only; retained prior editions MUST NOT be served, the service serving one kind `30641` per `(author, d)` as [NIP-01](https://nips.nostr.com/1) addressable replacement requires. Two writers on one alias therefore share one ring and halve each other's retained history. MUST reject any event of the kinds in this document whose `created_at` is more than 900 seconds in the future.

## Encrypted Streams

Kind `3359` carries stored encrypted stream traffic and kind `23359` is its ephemeral analog. MUST admit these kinds only when the signer is a `w` or `aux` key of a live registration and the event passes the size, skew, quota and rate gates. MUST NOT inspect their content. MUST reject an event of these kinds signed by a key in no live registration, rather than falling through to the GRASP-01 related-event path. A kind `23359` event MUST NOT be stored.

These events are not [NIP-59](https://nips.nostr.com/59) gift wraps and MUST NOT use kind `1059`. NIP-59 encrypts its kind `13` seal with [NIP-44](https://nips.nostr.com/44) pairwise to one recipient, which cannot carry the group symmetric AEAD envelope these events use; and it requires the wrap to be signed by a random one-time key, where admission control here requires a signer derived deterministically by the group. NIP-59 further recommends that relays AUTH-gate kind `1059` and serve it only to the p-tagged recipient; these events carry no `p` tag, so a relay adopting that recommendation would stop serving them. Kind `1059` remains available for genuine NIP-59 use.

## Blob Store

MUST serve the [Blossom](https://github.com/hzrd149/blossom) subset BUD-01 (`GET /<sha256>`, `HEAD /<sha256>`), BUD-02 (`PUT /upload`) and BUD-06 (`HEAD /upload`). `DELETE /<sha256>` and `GET /list/<pubkey>` are BUD-12, which marks `/list` unrecommended. Authorization is BUD-11's kind `24242` event, carried as `Authorization: Nostr <token>` where `<token>` is the event JSON encoded base64url without padding, as BUD-11 requires; a service SHOULD also accept standard base64 and padded forms.

MUST verify the event's id and signature, that its `t` tag is the verb BUD-11 assigns that endpoint, that its `expiration` ([NIP-40](https://nips.nostr.com/40)) is present, numeric and in the future, and, for each endpoint where BUD-11 requires `x`, that an `x` tag equals the sha256 being operated on. MUST reject an authorization whose `created_at` is more than 3600 seconds in the past or more than 900 seconds in the future, whatever its `expiration`. MUST reject an authorization that carries BUD-11 `server` tags none of which names this service's own host, and MUST require such a tag on the authorization for `GET /list/<pubkey>`; SHOULD require it for the other endpoints once clients send it. These two checks are stateless; a service is not required to remember authorizations it has seen. As an additional requirement this service places on the `24242` event for `PUT /upload`, `HEAD /upload` and `DELETE /<sha256>`, it MUST carry an `a` tag of `30640:<tenant-hex>:<alias>` and MUST be rejected unless its signer is in that registration's `w` set. `GET /<sha256>` and `HEAD /<sha256>` are UNAUTHENTICATED. `GET /list/<pubkey>`, if served, MUST require a `24242` authorization whose `t` tag is `list` and whose signer is the pubkey in the path; neither an `x` nor an `a` tag is required, and membership of a `w` set does not qualify a key. Every request that lacks such an authorization MUST get one identical response (status, any reason text, and body), whether the pubkey has blobs, has none or is unknown to the service, decided without consulting any registration; a path segment that is not a pubkey MAY be rejected as malformed before that. A `/list` refused for a missing or foreign `server` tag gets that same response. An open `/list` would hand any anonymous party a hosting pubkey's whole stored inventory in one request, including blobs no served state root names. Gating it does not hide that a pubkey is hosted or which blobs its current state roots name: registrations and state roots stay public (see Caveats).

A response to `GET /<sha256>` or `HEAD /<sha256>` MUST NOT allow a cache to reuse the blob without asking the service (reference: `Cache-Control: no-cache` with the sha256 as a strong `ETag`), and a conditional request MUST NOT be answered `304` for a blob the service would otherwise refuse or does not hold: a takedown has to reach caches. Error responses SHOULD say `Cache-Control: no-store`. SHOULD send `X-Content-Type-Options: nosniff`, and with a blob a `Content-Security-Policy` that makes it inert in a browser (reference: `default-src 'none'; sandbox`). A `401` SHOULD carry `WWW-Authenticate: Nostr`, and no other status should. The `uploaded` member of a blob descriptor is the time this service first stored the blob.

A service MAY limit how many uploads are in flight, per hosting pubkey and in total, and how long an upload body may take. A `PUT /upload` refused for such a limit MUST NOT be answered with the status used for exhausted storage (reference: `507`), since a client would read it as a full quota: SHOULD answer `429` when the limit is the hosting pubkey's own and `503` when it is the service's, each with `Retry-After`, and `408` for a body that stalls or exceeds its time (reference: 8 uploads per hosting pubkey, 64 per service, 30 seconds between two pieces of a body, and 30 seconds plus the declared length at 16384 bytes per second in total). Such a refusal MUST leave nothing stored and nothing charged. Fetches a service makes to replicate blobs from another service SHOULD NOT be counted against the limits its clients share. These limits are local to a service and two services that replicate each other need not agree on them.

## NIP-11

MUST list this GRASP's number under `supported_grasps`, as GRASP-01 requires. SHOULD also advertise a top-level `private_repos` object carrying at least `kinds` (eg. `[30640, 30641, 3359, 23359]`), which MUST track the kinds actually admitted; other members are implementation-defined.

## Rejection Messages

MUST use these NIP-01 `OK` messages, with the prefixes shown. A stored event rejected as `unregistered alias` or `unregistered key` SHOULD be kept in purgatory — not served — and admitted if a later kind `30640` makes it admissible, and MUST be discarded within 30 minutes; an ephemeral event MUST NOT be held.

| Condition | Message |
|---|---|
| kind `30641`, no live registration for the alias | `restricted: unregistered alias` |
| stream wrap, signer unclaimed or alias not live | `restricted: unregistered key` |
| kind `30641`, registration identity changed mid-transaction | `restricted: alias registration changed; retry` |
| stream wrap, registration identity changed mid-transaction | `restricted: registration changed; retry` |
| kind `30640`, same-tenant replacement over cadence | `rate-limited: replacement over cadence; retry later` |
| client write bucket exhausted | `rate-limited: retry later` |
| kind `30640` lost an alias conflict | `restricted: alias already registered` |
| kind `30640` lost a key conflict | `restricted: write key already registered` |
| `created_at` beyond the future skew | `invalid: event created_at is too far in the future` |

## Becoming Public

A repository becomes public when a client pushes its decrypted history to this service over GRASP-01's git smart HTTP and then publishes a [NIP-34](https://nips.nostr.com/34) kind `30617` announcement and kind `30618` state, followed by an author-valid NIP-09 kind `5` deletion of its kind `30640` and `30641` events, which frees their blob claims. The service MUST NOT be expected to derive plaintext from anything it holds. The public `d` tag is a real identifier, so publication permanently links the repository to its former alias.

## Caveats

The service verifies signatures against opaque keys and moves bytes; it cannot read repository names, refs, contributor identities or file contents. It does learn, and MUST be assumed to publish: the hosting pubkey, the alias, the registered keys, blob hashes, sizes and timing, and epoch lineage across rotations. The relay stays public-read, so ciphertext harvest by any anonymous party is conceded, not prevented. Confidentiality rests on client-side encryption alone; a removed member keeps every ciphertext and key they already held.
