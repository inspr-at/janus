#!/bin/sh
set -eu
cd "$(dirname "$0")"
GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" go run ./cmd/check-version
exec go build "$@"
