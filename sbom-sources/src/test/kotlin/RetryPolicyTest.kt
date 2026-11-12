/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.apoapsis.sbom.sources

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

class RetryPolicyTest : WordSpec({
    val policy = RetryPolicy(maxRetries = 6, initialDelay = Duration.ofSeconds(2), maxDelay = Duration.ofSeconds(30))

    "delayBefore" should {
        "double the delay up to the maximum delay" {
            (1..6).map { policy.delayBefore(it).seconds } shouldBe listOf(2L, 4L, 8L, 16L, 30L, 30L)
            policy.delayBefore(1000) shouldBe Duration.ofSeconds(30)
        }

        "wait longer if the server asks for it with Retry-After, up to the maximum delay" {
            policy.delayBefore(1, "10") shouldBe Duration.ofSeconds(10)
            policy.delayBefore(3, "1") shouldBe Duration.ofSeconds(8)
            policy.delayBefore(1, "3600") shouldBe Duration.ofSeconds(30)
        }

        "accept a date in Retry-After" {
            val now = Instant.parse("2026-11-12T15:32:27Z")

            policy.delayBefore(1, "Thu, 12 Nov 2026 15:32:47 GMT", now) shouldBe Duration.ofSeconds(20)
            policy.delayBefore(1, "Thu, 12 Nov 2026 15:00:00 GMT", now) shouldBe Duration.ofSeconds(2)
        }

        "ignore an invalid Retry-After" {
            policy.delayBefore(1, "soon") shouldBe Duration.ofSeconds(2)
        }
    }

    "RetryPolicy" should {
        "reject invalid values" {
            shouldThrow<IllegalArgumentException> { RetryPolicy(maxRetries = -1) }
            shouldThrow<IllegalArgumentException> { RetryPolicy(initialDelay = Duration.ofSeconds(-1)) }
            shouldThrow<IllegalArgumentException> {
                RetryPolicy(initialDelay = Duration.ofSeconds(10), maxDelay = Duration.ofSeconds(5))
            }
        }
    }

    "RetryingSender" should {
        "wait the delays of the policy and of Retry-After between the retries" {
            MockSbomServer().use { server ->
                server.respond("/sbom.json", "{}".toByteArray())
                server.failNext("/sbom.json", status = 503)
                server.failNext("/sbom.json", status = 429, headers = mapOf("Retry-After" to "5"))
                val delays = mutableListOf<Duration>()
                val sender = RetryingSender(HttpClient.newHttpClient(), policy) { delays += it }

                val (response, retries) = sender.send(
                    HttpRequest.newBuilder(URI("${server.baseUrl}/sbom.json")).build(),
                    HttpResponse.BodyHandlers.ofString()
                )

                response.statusCode() shouldBe 200
                retries shouldBe 2
                delays shouldBe listOf(Duration.ofSeconds(2), Duration.ofSeconds(5))
            }
        }
    }
})
