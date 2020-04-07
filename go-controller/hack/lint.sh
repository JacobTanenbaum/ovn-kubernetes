#!/usr/bin/env bash

GO111MODULE=on ${GOPATH}/bin/golangci-lint run \
    --skip-dirs=pkg/crd/egressfirewall/v1/apis/ \
    --tests=false --enable gofmt \
    --timeout=10m0s \
    && echo "lint OK!"
