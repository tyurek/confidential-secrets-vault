# go 1.26 is required: the vault uses the crypto/hpke stdlib package.
# Pin the builder/runtime by digest before release (see confidential-model-router).
FROM golang:1.26-alpine AS builder

WORKDIR /app

# NOTE for publishing: this prototype pins encrypted-http-body-protocol via a
# local `replace` in go.mod for dev. Replace it with the tagged module version
# before building this image, or `go mod download` fails without the sibling
# checkout in the build context.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o vault .

FROM alpine:3.23

WORKDIR /app

COPY --from=builder /app/vault .

EXPOSE 8080

# Always runs behind the tinfoil shim: the shim terminates EHBP and serves the
# HPKE key, so the vault reads plaintext /store and verifies workloads via SNP.
ENTRYPOINT ["./vault", "-behind-shim", "-addr", ":8080"]
