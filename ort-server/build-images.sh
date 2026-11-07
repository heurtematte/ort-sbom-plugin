#!/usr/bin/env bash
#
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# https://www.eclipse.org/legal/epl-2.0
#
# SPDX-License-Identifier: EPL-2.0

# Build the images of the ORT Server core and analyzer worker with the ORT SBOM plugin.
#
# Usage: ort-server/build-images.sh [ORT_SERVER_VERSION] [TARGET_PREFIX]
#
# The images are tagged "<TARGET_PREFIX>/ort-server-core:<ORT_SERVER_VERSION>" and
# "<TARGET_PREFIX>/ort-server-analyzer-worker:<ORT_SERVER_VERSION>". Set SOURCE_PREFIX to use base images from another
# registry than ghcr.io/eclipse-apoapsis, and PUSH=1 to push the images. Set MIRROR=1 to also copy the other images of
# ORT Server to TARGET_PREFIX, so that the Helm chart of ORT Server can use them all with "containerRegistry".
set -euo pipefail

version="${1:-0.99.1}"
target_prefix="${2:-ort-server-sbom}"
source_prefix="${SOURCE_PREFIX:-ghcr.io/eclipse-apoapsis}"

cd "$(dirname "$0")/.."
./gradlew --console=plain -q ortServerPlugin

for component in core analyzer-worker; do
    image="$target_prefix/ort-server-$component:$version"
    echo "Building $image"
    docker build \
        -f ort-server/Dockerfile \
        --build-arg "BASE_IMAGE=$source_prefix/ort-server-$component:$version" \
        -t "$image" \
        build/ort-server-plugin

    if [ "${PUSH:-0}" = 1 ]; then
        docker push "$image"
    fi
done

if [ "${MIRROR:-0}" = 1 ]; then
    for component in advisor-worker config-worker evaluator-worker maintenance-tasks orchestrator reporter-worker \
        scanner-worker ui; do
        echo "Copying ort-server-$component:$version"
        docker buildx imagetools create \
            -t "$target_prefix/ort-server-$component:$version" \
            "$source_prefix/ort-server-$component:$version"
    done
fi
