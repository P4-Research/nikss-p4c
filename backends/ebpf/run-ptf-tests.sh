#!/bin/bash

target="${*:$#}"
cd "$(dirname "$target")" || exit 1

ARGS=""
if [ "x$1" = "x--xdp" ]; then
  ARGS="--xdp"
fi

bash "$target" $ARGS
