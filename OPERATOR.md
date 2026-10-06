# Running a cosigner

You run a program that signs what it sees in the Sigelith log. Your signature counts as one
of three. You need a Linux host with Docker, an accurate clock, and outgoing HTTPS. No
open ports, no domain, no reverse proxy.

## 1. Install

```bash
mkdir -p /srv/sigelith-cosigner
chown 65532:65532 /srv/sigelith-cosigner        # the container runs as nonroot (uid 65532)
```

Copy `compose.yml` from this repository and set:

- `image:` — the digest from the release notes (never a tag: a tag can be moved, a digest
  cannot);
- `COSIGNER_NAME` — a stable name of the operator, `[a-z0-9-]`, up to 32 characters, chosen
  once and never changed (moving to another host does not change the operator).

```bash
docker compose up -d
docker compose logs sigelith-cosigner | head -1
```

The first line shows your **public key**. Send it to Sigelith through a channel you trust.
The key was generated on your host and never left it.

## 2. The key

`/srv/sigelith-cosigner/cosigner.key` is the only copy of your private key (32 bytes). Back
it up like a safe, not like application data. If it is lost, generate a new one by removing
the file and send the new public key — the old signatures stay valid. If it may have been
copied, tell Sigelith at once: the key is withdrawn from the key list.

`state.json` next to it is what the cosigner remembers between runs. Losing it is harmless:
the cosigner starts over and its next signature says `since: null`.

## 3. Clock

The cosigner judges every entry's time by **your** clock. Run NTP (chrony, systemd-timesyncd).
If your clock is off by more than 30 seconds, the cosigner stops itself rather than sign —
that is intended.

## 4. Alarm

On an anomaly the log line says `ALARM:` and the cosigner signs nothing more. Possible causes:

- `lancuch przerwany` / `chain_hash nie wynika` — the log's history changed: **report it** to
  Sigelith and keep the state file, it is evidence;
- `datowany wstecz` — an entry appeared older than your previous observation: **report it**;
- `pozniejszy niz zegar straznika` — usually your clock: fix it first;
- `nie zgadza sie` — the log rejected your signed tree: **report it**.

After you have decided, clear the alarm:

```bash
docker compose run --rm sigelith-cosigner clear-alarm
docker compose restart sigelith-cosigner
```

Clearing also forgets the previous observation time, so your next signature makes no claim
about the time before it.

## 5. Updates

Each release lists the new image digest and how to verify its cosign signature. Replace the
digest in `compose.yml`, then `docker compose up -d`. The key and the state stay in
`/srv/sigelith-cosigner`.

## 6. Resources

One HTTPS request per minute to the log (a few kB), one signature per new minute of entries
or per hour. Memory ~10 MB, CPU negligible.
