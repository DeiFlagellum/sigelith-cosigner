# sigelith-cosigner

An independent witness for the [Sigelith](https://sigelith.org) proof-of-existence log.
Every minute it reads the public log, checks the hash chain and every entry's time **against
its own clock**, recomputes the RFC 9162 Merkle tree itself, and signs what it saw
(`sigelith-cosign-v1`). The log stores and hands out the signature; it cannot make or alter it.

A Sigelith stamp is trusted when **any two of three** signatures support it: the log's own
key, the cosigner Sigelith runs in AWS (key in AWS KMS, a hardware security module), and a
cosigner run by an independent operator. Backdating a stamp would take breaking into two
separate systems.

- **No inbound interface.** The cosigner only makes outgoing HTTPS requests. Nothing can ask
  it to sign.
- **Fail-stop.** A broken chain, a backdated entry, an entry from the future or a log that
  disagrees with the signed tree stops the cosigner until its operator decides.
- **Small.** Go standard library only, no third-party code. Image: distroless, ~16 MB,
  no shell. Reproducible build, images signed with cosign.

Protocol: [PROTOCOL.md](PROTOCOL.md). Running it: [OPERATOR.md](OPERATOR.md) (container) or
[AWS.md](AWS.md) (AWS Lambda with a KMS key).

## Quick start (operator)

```bash
mkdir -p /srv/sigelith-cosigner && chown 65532:65532 /srv/sigelith-cosigner
# compose.yml from this repository: set COSIGNER_NAME and the image digest
docker compose up -d
docker compose logs sigelith-cosigner | head -1     # your public key
```

Send the public key to Sigelith. Your signatures count from the moment the key is on the
Sigelith key list (`/spec/#cosigners`) and in the Sigelith apps.

## Verify what you run

```bash
cosign verify ghcr.io/deiflagellum/sigelith-cosigner@sha256:<digest> \
  --certificate-identity-regexp 'github.com/DeiFlagellum/sigelith-cosigner' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Or rebuild it: `docker build --build-arg VERSION=<x.y.z> .` gives the same binary as the
release (`go build -trimpath -ldflags="-s -w -buildid= -X main.version=<x.y.z>"`).

## Build and test

```bash
go test ./...
go run ./tools/vector                  # the test vector of PROTOCOL.md
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -buildid=" -o bootstrap .
go run ./tools/lambdazip bootstrap sigelith-cosigner-lambda-arm64.zip
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Security reports:
[SECURITY.md](SECURITY.md).
