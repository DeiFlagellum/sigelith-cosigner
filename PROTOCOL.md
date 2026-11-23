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
8. **Hourglass**: check the new segments of every clock in the log and deliver confirmations
   (section 9). A problem there never stops steps 1 to 7.

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

## 9. Hourglass segments

Sigelith Hourglass is a clock of sequential work: a chain of segments, each a proof of
sequential work (Cohen and Pietrzak, on SHA-256) whose seed takes the root of the segment
before and fresh inputs. Specification: the `sigelith-hourglass` repository, `SPEC.md`. The log
publishes every segment of every clock and stamps it like any other document:

| request | answer |
|---|---|
| `GET /api/hourglass/clocks` | `clocks`: for each clock with a published genesis `clock`, `operator`, `genesis_root`, `latest_segment`, `latest_root` |
| `GET /api/hourglass/<clock>/genesis` | the exact bytes of `genesis.json` |
| `GET /api/hourglass/<clock>/segments/<j>` | the exact bytes of the signed record of segment `j` |
| `GET /api/hourglass/<clock>/segments/<j>/proof` | the proof, `t * n * 32` bytes |

After step 7 of every run, for each clock on the list, the cosigner:

1. **Pins the genesis** the first time it sees the clock: it fetches `genesis.json`, checks it
   and computes its root `phi_0` itself. The file must be canonical JSON and match the list.
2. **Compares the list with what it checked**: the same genesis, a chain that did not get
   shorter, and the same root for the last segment it checked.
3. **Checks every new segment in order**, with the full proof, as `check_segment` of the
   specification: the record is canonical JSON with exactly the v1 fields; `prev_root` is the
   root of the segment before; the seed follows from it and the inputs; the proof passes all
   `t` checks; `claim_permille` and `coverage_permille` follow from the record; the signature
   verifies with the operator key, which the cosigner pins at the first segment; `utc_end` is
   not later than the cosigner's clock plus 30 s.
4. **Signs a confirmation** for each segment that passed and delivers it:
   `POST /api/hourglass/confirm`. At most 4 segments per run, and none started once the run is
   12 s old; the rest waits for the next run.

```
body = {
  "v": "sigelith-hourglass-confirm-v1",
  "log": "<log host, e.g. sigelith.org>",
  "cosigner": "<name: [a-z0-9-], up to 32 characters>",
  "key": "<Ed25519 public key of the cosigner, base64, 32 bytes>",
  "clock": "<clock name: [a-z0-9-], up to 32 characters>",
  "genesis": "<phi_0, the root of the clock's genesis, hex>",
  "j": <segment number, from 1>,
  "root": "<the root of segment j, hex>",
  "record": "<SHA-256 of the published bytes of the record, hex>",
  "time": "<cosigner clock after the check, YYYY-MM-DDTHH:MM:SS.ffffffZ>"
}
message  = ASCII("sigelith-hourglass-confirm-v1|") || JCS(body)
sig      = base64(Ed25519(key, message))
document = JCS(body + {"sig": sig})
```

**What a confirmation says.** By the cosigner's clock, no later than `time`, the record of
segment `j` with this SHA-256, as the log published it, was valid, and the chain from the
genesis `genesis` up to it held, every segment checked by the cosigner itself. The record
digest binds the rest: the inputs, the digest of the proof and the operator's signature. The
time of a segment is still what the log stamps and the cosigners sign under sections 3 to 5;
the confirmation adds an independent check of the work itself.

**An alarm stops one clock.** A segment that fails, a changed genesis or root, a shorter
chain, a new operator key, a segment from the future of the cosigner's clock or a 409 from the
log stops the confirmations of that clock only, until the operator of the cosigner decides:
`clear-hourglass-alarm <clock>`, or the Lambda test event
`{"clear_hourglass_alarm": "<clock>"}`. Clearing forgets the pinned operator key (that is how
a key change goes through), never the position in the chain: a changed history raises the
alarm again. Log cosigning and the other clocks go on; in Lambda the invocation still ends with
an error, so that the alarm is noticed.

**Contract with the log.** `201` / `200` stored or already stored; `409` the confirmation does
not match the published segment: alarm for that clock (the log keeps the document as evidence
and never shows it as a confirmation); `400` / `403` dropped and logged; any other status:
kept and retried. Up to 50 confirmations wait; a full queue pauses checking, so none is ever
dropped. The log publishes them per segment:
`GET /api/hourglass/<clock>/segments/<j>/confirmations`, the earliest confirmation of each
cosigner. Check each one with the cosigner's key from `/spec/#cosigners` (section 7, point 1).

**Test vector.** Segment 1 of the v1 example chain in `vectors/vectors.json` of
`sigelith-hourglass`, key from seed `0x22` * 32 (`go run ./tools/vector`):

```
message: sigelith-hourglass-confirm-v1|{"clock":"example","cosigner":"example","genesis":"cffd45246dd3587f6758d83d98a6b3c326a7de8375f4f292a1a7b2ac33f67df3","j":1,"key":"oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=","log":"sigelith.org","record":"ad361cf1c947ae7020a093c0a463e6c33ddd3ab74f38483f64dcba1f2761d9c5","root":"98811eb2bf58bd526b46e2cc70edee67eed1cb0d448f5c46a87b138babc4fef7","time":"2026-11-23T00:01:00.250000Z","v":"sigelith-hourglass-confirm-v1"}
sig:     BNcmZ7uWARNQUbIs7ojWDThSv4laLXuL/zl6+uO7D0STPJ6yt1LTqqh0Yf/vY8hkLRsN0CB9JZLTPfGXetwtBg==
```

The check of segments in `internal/hourglass` is an independent implementation of the
specification in Go; it gives the same bytes and the same decisions as the reference
implementation on its test vectors (`internal/hourglass/testdata`).

## 10. Publishing your own clock

An independent operator who runs an Hourglass clock publishes it with the same program,
under a separate key. The prover never holds a key; the key is `clock.key` in the data
directory, created on the operator's host.

- `clock-key` prints the public key of the clock. Send it to Sigelith together with `phi_0` of
  the genesis; the log accepts the clock once both are pinned there.
- `clock-push` runs every minute. It reads the prover's directory (read only): `genesis.json`,
  `segments/<j>.json` and `segments/<j>.proof`, records without a signature. It takes the
  clock's position from `GET /api/hourglass/clocks` and compares it with its own files; a
  different root at the same segment stops it, and nothing is sent.
- Each new record is checked as in section 9 point 3, without the signature, and then signed:
  `key` is added, and `sig = base64(Ed25519(clock key, ASCII("sigelith-hourglass-segment-v1|")
  || JCS(record without sig)))`, as `SPEC.md` section 8 defines.
- It sends `{"clock", "genesis"}` once, then `{"clock", "record", "proof"}` for every segment in
  order, the proof in base64: `POST /api/hourglass/push`. The log checks the record again with
  the pinned key and the reference implementation, stamps it and publishes it. A `403` means the
  clock is not pinned yet; `clock-push` waits and says which key and `phi_0` to send.
- It keeps no state between runs. Ed25519 is deterministic, so sending a segment again gives
  exactly the same bytes.
