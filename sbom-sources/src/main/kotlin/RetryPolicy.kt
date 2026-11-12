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

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.time.Duration
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.concurrent.ConcurrentHashMap

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(RetryPolicy::class.java)

/**
 * How requests to SBOM sources are retried when a server is temporarily unavailable: when no response is received, for
 * instance because the connection is refused or reset, or when the server answers with one of the
 * [RETRYABLE_STATUSES]. Other statuses, such as 401 or 404, and requests that time out after the request timeout are
 * not retried, as a retry would fail the same way.
 *
 * The delay before a retry starts with [initialDelay] and doubles with each retry, up to [maxDelay]. If the server asks
 * for a longer delay with the `Retry-After` header, that delay is used, also up to [maxDelay]. With the default values,
 * a request is retried five times within about one minute.
 */
data class RetryPolicy(
    /** The maximum number of retries of a request; 0 disables retries. */
    val maxRetries: Int = DEFAULT_MAX_RETRIES,

    /** The delay before the first retry. */
    val initialDelay: Duration = Duration.ofSeconds(DEFAULT_INITIAL_DELAY_SECONDS),

    /** The maximum delay before a retry. */
    val maxDelay: Duration = Duration.ofSeconds(DEFAULT_MAX_DELAY_SECONDS)
) {
    companion object {
        private const val DEFAULT_MAX_RETRIES = 5
        private const val DEFAULT_INITIAL_DELAY_SECONDS = 2L
        private const val DEFAULT_MAX_DELAY_SECONDS = 30L

        /** The maximum exponent of the backoff, to keep the doubled delay from overflowing. */
        private const val MAX_BACKOFF_EXPONENT = 20

        /** Do not retry requests. */
        val NONE = RetryPolicy(maxRetries = 0)

        /**
         * The statuses of responses that are retried: 408 (Request Timeout), 429 (Too Many Requests), 502 (Bad
         * Gateway), 503 (Service Unavailable), and 504 (Gateway Timeout).
         */
        val RETRYABLE_STATUSES = setOf(408, 429, 502, 503, 504)
    }

    init {
        require(maxRetries >= 0) { "The maximum number of retries must not be negative, but is $maxRetries." }
        require(!initialDelay.isNegative) { "The initial delay must not be negative, but is $initialDelay." }
        require(maxDelay >= initialDelay) { "The maximum delay $maxDelay must not be shorter than the initial delay." }
    }

    /**
     * Return the delay before the given [retry], counted from 1, given the value [retryAfter] of the `Retry-After`
     * header of the failed response, if any, which is either a number of seconds or a date relative to [now].
     */
    fun delayBefore(retry: Int, retryAfter: String? = null, now: Instant = Instant.now()): Duration {
        val backoff = initialDelay.multipliedBy(1L shl (retry - 1).coerceIn(0, MAX_BACKOFF_EXPONENT))
        val requested = retryAfter?.let { parseRetryAfter(it, now) } ?: Duration.ZERO

        return minOf(maxOf(backoff, requested), maxDelay)
    }
}

/** Return the delay requested by the given value of a `Retry-After` header, or *null* if it is invalid. */
private fun parseRetryAfter(value: String, now: Instant): Duration? {
    val trimmed = value.trim()

    trimmed.toLongOrNull()?.let { seconds -> return Duration.ofSeconds(seconds.coerceAtLeast(0)) }

    return try {
        val date = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()
        Duration.between(now, date).takeUnless { it.isNegative } ?: Duration.ZERO
    } catch (_: DateTimeParseException) {
        null
    }
}

/** A [response] received after the given number of [retries]. */
internal data class RetriedResponse<T>(val response: HttpResponse<T>, val retries: Int)

/**
 * Send requests with the given [client], retrying them according to the given [policy].
 *
 * Once the retries of a request to an origin are exhausted, further requests to that origin are sent only once, until
 * one of them gets a response that is not retried. So, if a server is down, the retrieval of many sources from it does
 * not wait for the retries of each source.
 */
internal class RetryingSender(
    private val client: HttpClient,
    private val policy: RetryPolicy,
    private val sleep: (Duration) -> Unit = { Thread.sleep(it) }
) {
    /** The origins whose last request exhausted its retries. */
    private val unavailableOrigins: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /**
     * Send the given [request] and return the response with the number of retries, which may have a retryable status
     * if the retries are exhausted. Throw an [IOException] if no response is received; if the request was retried, its
     * message gives the number of retries.
     */
    fun <T> send(request: HttpRequest, bodyHandler: HttpResponse.BodyHandler<T>): RetriedResponse<T> {
        val url = request.uri()
        val origin = url.origin()
        var retries = 0

        while (true) {
            val (response, failure) = try {
                client.send(request, bodyHandler) to null
            } catch (e: IOException) {
                if (!e.isRetryable()) throw e
                null to e
            }

            if (response != null && response.statusCode() !in RetryPolicy.RETRYABLE_STATUSES) {
                unavailableOrigins -= origin
                return RetriedResponse(response, retries)
            }

            if (retries >= policy.maxRetries || origin in unavailableOrigins) {
                if (retries > 0) unavailableOrigins += origin

                return when {
                    response != null -> RetriedResponse(response, retries)
                    retries == 0 -> throw checkNotNull(failure)
                    else -> throw IOException("${checkNotNull(failure).describe()} (after $retries retries)", failure)
                }
            }

            retries++

            val retryAfter = response?.headers()?.firstValue("Retry-After")?.orElse(null)
            val delay = policy.delayBefore(retries, retryAfter)

            logger.warn(
                "Request to '{}' failed with {}; retry {} of {} in {} ms.",
                url.withoutQuery(),
                response?.let { "status ${it.statusCode()}" } ?: checkNotNull(failure).describe(),
                retries,
                policy.maxRetries,
                delay.toMillis()
            )

            sleep(delay)
        }
    }
}

/**
 * Return whether a request that failed with this exception is retried: all failures to get a response are retried,
 * except a request timeout, as a retry would wait as long again.
 */
private fun IOException.isRetryable(): Boolean = this !is HttpTimeoutException || this is HttpConnectTimeoutException

/** Describe this exception, whose message may be missing, such as for a refused connection. */
internal fun IOException.describe(): String = message?.takeUnless { it.isBlank() } ?: javaClass.name

/** Return the origin of this URL, consisting of the scheme, host, and port. */
private fun URI.origin(): String {
    val port = port.takeIf { it != -1 } ?: if (scheme.equals("https", ignoreCase = true)) 443 else 80
    return "${scheme.lowercase()}://${host.orEmpty().lowercase()}:$port"
}

/** Return this URL without query, which may contain signatures for pre-signed downloads, for messages. */
internal fun URI.withoutQuery(): String = toString().substringBefore('?')
