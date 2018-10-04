#!/bin/bash

if [[ -z "$HEROKU_ROUTER_HTTP_PORT" ]]; then
        exit 0
fi

PATH=/app/bin:$PATH ./bin/envoy-runner &
export PORT=8080
