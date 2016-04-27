#!/usr/bin/env bash
set -eux
DYLD_INSERT_LIBRARIES=dump.dylib "$@"
