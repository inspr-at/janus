FROM golang:1.26.6-alpine3.24@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG JANUS_BUILD_COMMIT=unknown
ARG JANUS_BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X 'main.buildCommit=${JANUS_BUILD_COMMIT}' -X 'main.buildTime=${JANUS_BUILD_TIME}'" -o /out/janus .

FROM alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
LABEL org.opencontainers.image.title="Janus governance envelope"
LABEL org.opencontainers.image.source="https://github.com/inspr-at/janus"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
LABEL org.opencontainers.image.base.name="docker.io/library/alpine:3.22.5"
LABEL org.opencontainers.image.base.digest="sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
# CVE-2026-14456: libcrypto3/libssl3 3.5.8-r0
RUN apk add --no-cache libcrypto3=3.5.8-r0 libssl3=3.5.8-r0
RUN addgroup -S janus && adduser -S -G janus janus
WORKDIR /app
COPY --from=build /out/janus /app/janus
RUN mkdir -p /data && chown janus:janus /data
USER janus
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/readyz | grep -q '"ready":true' || exit 1
ENTRYPOINT ["/app/janus"]
