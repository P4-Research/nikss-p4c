#!/bin/bash

target="${*:$#}"
cd "$(dirname "$target")" || exit 1

bash "$target"
