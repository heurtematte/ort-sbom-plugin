# syntax=docker/dockerfile:1
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

# Add the ORT SBOM plugin to an image of ORT Server (core or analyzer worker), without rebuilding ORT Server.
#
# The images of ORT Server start Java with the classpath listed in "/app/jib-classpath-file". This build adds the jars
# of the plugin to "/app/plugins" and appends "/app/plugins/*" to that classpath. It fails if the image does not contain
# the version of ORT the plugin was compiled against, or if it already contains the plugin.
#
# The build context is the directory created by "./gradlew ortServerPlugin" (build/ort-server-plugin), for instance:
#
#   docker build -f ort-server/Dockerfile \
#     --build-arg BASE_IMAGE=ghcr.io/eclipse-apoapsis/ort-server-core:0.103.0 \
#     -t ort-server-core-sbom:0.103.0 build/ort-server-plugin

ARG BASE_IMAGE=ghcr.io/eclipse-apoapsis/ort-server-core:0.103.0

FROM ${BASE_IMAGE} AS base

FROM busybox:1.37 AS classpath

COPY --from=base /app/jib-classpath-file /work/classpath
COPY required-libs.txt expected-libs.txt /work/

RUN <<'CHECK'
set -eu
cd /work
tr ':' '\n' < classpath | sed 's#.*/##' > present.txt

if grep -q '^sbom-package-manager-' present.txt; then
    echo 'error: The base image already contains the SBOM plugin.'
    exit 1
fi

missing=$(grep -vxFf present.txt required-libs.txt || true)
if [ -n "$missing" ]; then
    echo 'error: The base image does not contain these ORT libraries the plugin was compiled against:'
    echo "$missing"
    echo 'Build the plugin with the ORT version of the base image (see settings.gradle.kts).'
    exit 1
fi

different=$(grep -vxFf present.txt expected-libs.txt || true)
if [ -n "$different" ]; then
    echo 'warning: The base image contains other versions of these libraries the plugin uses:'
    echo "$different"
fi

printf '%s:/app/plugins/*' "$(cat classpath)" > classpath.new
CHECK

FROM ${BASE_IMAGE}

COPY --from=classpath /work/classpath.new /app/jib-classpath-file
COPY plugins/ /app/plugins/

LABEL org.opencontainers.image.description="ORT Server with the ORT SBOM plugin"
LABEL org.opencontainers.image.source="https://github.com/heurtematte/ort-sbom-plugin"
LABEL org.opencontainers.image.licenses="EPL-2.0 AND Apache-2.0"
