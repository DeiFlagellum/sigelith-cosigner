# syntax=docker/dockerfile:1

# Budowa statyczna i powtarzalna (jak beat-key): -trimpath usuwa sciezki
# budowy, -buildid= niedeterministyczny identyfikator, CGO_ENABLED=0 daje
# binarke bez zaleznosci systemowych. Dwie budowy z tego samego commitu daja
# ten sam artefakt — operator moze odbudowac obraz i porownac digest.
FROM golang:1.26-alpine AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY . .
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/sigelith-cosigner . \
 && mkdir -p /data \
 && chown 65532:65532 /data

# distroless/static: brak powloki i menedzera pakietow; sa tylko certyfikaty CA
# (HTTPS do dziennika) i strefy czasowe. Nie ma sie do czego zalogowac, wiec
# nie ma czym wyniesc klucza.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/sigelith-cosigner /sigelith-cosigner
COPY --from=build --chown=65532:65532 /data /data

USER nonroot:nonroot
# Zadnego EXPOSE: straznik nie ma drzwi. Sam pobiera wpisy i sam wysyla podpis.
ENTRYPOINT ["/sigelith-cosigner"]
CMD ["run"]
