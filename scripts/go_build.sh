#!/bin/bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./scripts/variables.sh

PLATFORM="${1:-all}"
case "${PLATFORM}" in
  all|android|ios) ;;
  *) printf 'Usage: %s [all|android|ios]\n' "$0" >&2; exit 1 ;;
esac

if [ "${PLATFORM}" != ios ]; then
  if ! grep -Eq '^Pkg.Revision = (2[89]|[3-9][0-9])\.' "${NDK_HOME}/source.properties"; then
    printf 'Android builds require NDK r28 or newer; set NDK_HOME (current: %s).\n' "${NDK_HOME}" >&2
    exit 1
  fi
  printf 'Using Android NDK: %s\n' "${NDK_HOME}"
fi

# Build iOS
cd ./go
if [ "${PLATFORM}" != android ]; then
  gomobile bind -target=ios -ldflags="-s -w" -o ../ios/Frameworks/GoCore.xcframework
fi

# Build android
if [ "${PLATFORM}" != ios ]; then
  gomobile bind -target=android -androidapi=21 -trimpath \
    -ldflags '-s -w -extldflags "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"' \
    -o ../spacemesh-go/spacemesh.aar

  rm -f ../spacemesh-go/spacemesh-sources.jar
fi
