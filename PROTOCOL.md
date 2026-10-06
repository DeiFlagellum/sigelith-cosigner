# sigelith-cosign-v1 — log cosigning protocol

This document is normative. `internal/` is its executable form; where the two disagree,
this document wins and the code has a bug.

## 1. Purpose

The Sigelith log (<https://sigelith.org>) records SHA-256 digests with the time it saw them.
Its own key signs every receipt and checkpoint. A key held by one operator, however, proves
only that the operator signed — not that the operator was honest about *when*.

A **cosigner** is an independent program, run on a different machine under a different
account, that watches the public log and signs what it saw, with a time taken **from its own
clock**. Sigelith runs one cosigner in AWS (key in AWS KMS); independent operators run others.
A stamp is trusted when **any two of three** signatures support it: the log key and the
cosigners. To forge or backdate a stamp, an attacker must break into two separate systems.

The cosigner has **no inbound interface**. It pulls the public log on its own schedule and
pushes its signature to the log. Nobody can ask it to sign anything; the log can store and
hand out its signatures, but cannot make or alter them.

## 2. Input: the public log

`GET /api/proof/entries?from=<seq>&limit=1000` returns entries in `seq` order and `next`
(the `from` of the next page, or `null` at the end). An entry:

| field | meaning |
|---|---|
| `seq` | strictly increasing, may have gaps; the tree position is the order, not the number |
| `digest` | SHA-256 of the document, 64 lowercase hex |
| `utc` | the log's time of the entry, `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `prev_chain`, `chain_hash` | hash chain, below |

```
chain_hash = hex(SHA-256(UTF-8(prev_chain || digest || chain_utc(utc))))     prev_chain of the first entry = 64 zeros
leaf       = SHA-256(0x00 || ASCII("beattime-entry-v1|" + seq + "|" + digest + "|" + utc))
node       = SHA-256(0x01 || left || right)                                    tree: RFC 9162 MTH, leaves in seq order
```

`chain_utc` is the historical form Python's `datetime.isoformat()` gives for UTC:
`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`, **without the fraction when microseconds are exactly 0**.
Full log specification: Sigelith `LOG.md`.

## 3. One run

Every minute (Lambda: EventBridge Scheduler; operator: a timer in the container):

1. **Load state.** If the state carries an alarm, stop (fail-stop, section 5).
2. `t_start` = own clock. Fetch every entry after the last one seen. `t_end` = own clock.
3. **Check each new entry**, in order:
   - `seq` grows; fields have the right shape;
   - `prev_chain` equals the previous `chain_hash`, and `chain_hash` recomputes;
   - `utc` does not go back in time relative to the previous entry;
   - `utc ≤ t_end + 30 s` — not from the future of the cosigner's clock;
   - `utc ≥ observed_at − 30 s`, where `observed_at` is `t_start` of the previous **complete**
     fetch — the entry was not in the log then, so it cannot be older than that. This is the
     check that stops backdating.

   Any failure: alarm, no signature.
4. **Extend the tree** with the new leaves (the cosigner keeps only the RFC 9162 frontier:
   one hash per set bit of the tree size) and compute the root itself. It never takes a root
   or a proof from the log.
5. **Sign** when the tree grew, or at least once an hour without new entries (a heartbeat
   that shows the cosigner is alive and the log has not been forked).
6. Save the state; `observed_at` = `t_start`, but only if the fetch reached the end of the
   log. Entries not yet fetched were not seen and may not be judged by this bound.
7. **Deliver** every undelivered signature: `POST /api/cosign` (section 6).

Tolerances: 30 s each way covers commit latency and clock difference between the log (its
clock is checked against PTB over NTS) and the cosigner (AWS Time Sync, or NTP at the
operator). A cosigner whose clock is wrong by more than that stops itself instead of
signing.

## 4. Format

```
body = {
  "v": "sigelith-cosign-v1",
  "log": "<log host, e.g. sigelith.org>",
  "cosigner": "<name: [a-z0-9-], up to 32 characters>",
  "key": "<Ed25519 public key of the cosigner, base64, 32 bytes>",
  "size": <tree size>,
  "root": "<RFC 9162 root at size, hex>",
  "last_seq": <seq of the last entry in the tree>,
  "last_chain_hash": "<its chain_hash>",
  "time": "<cosigner clock after the fetch, YYYY-MM-DDTHH:MM:SS.ffffffZ>",
  "since": {"size": <size at the previous observation>, "time": "<observed_at>"} | null
}
message  = ASCII("sigelith-cosign-v1|") || JCS(body)
sig      = base64(Ed25519(key, message))            pure Ed25519 (RFC 8032)
document = JCS(body + {"sig": sig})                 what is sent and archived
```

JCS is the subset of RFC 8785 used by Sigelith checkpoints: ASCII keys sorted, no spaces,
integers below 2^53, no trailing newline. `since` is `null` only for the first observation
(and after an operator clears an alarm).

## 5. What a cosignature says

For an entry at leaf index `i` (0-based) and a cosignature with `size`, `time` and `since`:

- `i < size`: the entry, with exactly this `seq`, `digest` and `utc`, was in the log no
  later than `time` by the cosigner's clock;
- `since.size ≤ i < size`: additionally, the entry was **not** in the log at `since.time`,
  and its `utc` lies within `[since.time − 30 s, time + 30 s]` — the cosigner checked it.

So the earliest cosignature that includes an entry brackets its time to the interval
between two observations, about a minute wide, by a clock the log operator does not control.

**Fail-stop.** On any anomaly the cosigner records an alarm and signs nothing more until its
operator decides. Clearing the alarm (`clear-alarm`, or the Lambda test event
`{"clear_alarm": true}`) also forgets `observed_at`, so the next signature has
`since: null` and claims nothing about the time before it.

## 6. Contract with the log

`POST /api/cosign` with the document as the request body (`application/json`):

| status | meaning | cosigner |
|---|---|---|
| 201 / 200 | stored / already stored | done |
| 409 | the log's own tree differs from the signed one | **alarm** — a fork or a bug |
| 400 / 403 | malformed, or the key is not a known cosigner | drop it, log |
| other | temporary | keep it, retry next run (up to 20 waiting) |

The log verifies the signature against its pinned list of cosigner keys and recomputes the
root at `size` before storing. It publishes, for any entry,
`GET /api/proof/cosign?digest=<hex>`: for each cosigner the earliest cosignature that
includes the entry, with the RFC 9162 audit path of the entry's leaf to that root.

## 7. Verifying, without trusting the log

1. Take the cosigner's public key from its operator or the Sigelith key list
   (`/spec/#cosigners`) — never from the cosignature alone.
2. Rebuild `message` from the document without `sig` and check the Ed25519 signature.
3. Recompute the entry's leaf from `seq`, `digest`, `utc` and verify the audit path to `root`
   with `leaf_index` and `size` (RFC 9162 2.1.3.2).
4. Read the time bounds of section 5.

**Test vector.** Body over the three entries of Sigelith `LOG.md` section 10 (tree size 3),
key from seed `0x22` × 32 (`go run ./tools/vector`):

```
key:     oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=
message: sigelith-cosign-v1|{"cosigner":"example","key":"oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=","last_chain_hash":"e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2","last_seq":4,"log":"sigelith.org","root":"bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d","since":{"size":2,"time":"2026-09-28T12:00:00.100000Z"},"size":3,"time":"2026-09-28T12:01:00.250000Z","v":"sigelith-cosign-v1"}
sig:     RTmvqX92rz679pXAt9aFdN3GbHk4tiUh3y25i5YqCh3TPw99kOy1jVVYn3Bc0I/5uury+QWNQHgYHRLTzTPvCg==
```

## 8. What it does not give

- An attacker who controls the log server can obtain cosignatures only for **new** entries
  with the **current** time — what any user of the public API can do anyway. He cannot get a
  backdated entry cosigned.
- An attacker who controls two of the three signers can forge. Two of them (the log server and
  the AWS account) belong to the same operator; the third belongs to an independent operator.
  Backdating also stays visible in the published, Bitcoin-anchored checkpoints.
- A stopped cosigner widens the time interval of the entries it confirms next; it never
  narrows it.
