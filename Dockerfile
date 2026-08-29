# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN build_date="${DATE}"; \
    if [ "${build_date}" = "unknown" ]; then build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; fi; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/codejavu-llc/ctscan/internal/cli.Version=${VERSION} -X github.com/codejavu-llc/ctscan/internal/cli.Commit=${COMMIT} -X github.com/codejavu-llc/ctscan/internal/cli.Date=${build_date}" \
      -o /ctscan .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /ctscan /ctscan
USER 65532:65532
ENTRYPOINT ["/ctscan"]
