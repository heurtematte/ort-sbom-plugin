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

package org.eclipse.apoapsis.sbom.parser

import java.nio.charset.Charset

private val UTF_32BE = Charset.forName("UTF-32BE")
private val UTF_32LE = Charset.forName("UTF-32LE")

/** A regular expression matching the encoding declaration of an XML document. */
private val XML_ENCODING_REGEX = Regex("""^(\s*<\?xml[^>]*?encoding\s*=\s*)(["'])[^"']*\2""")

/**
 * Return this content encoded as UTF-8 without byte order mark. Documents in UTF-16 or UTF-32 are recognized by their
 * byte order mark or, without one, by the zero bytes of ASCII characters, and converted. The encoding declaration of
 * an XML document is adapted accordingly.
 */
internal fun ByteArray.toUtf8(): ByteArray {
    val charset = detectCharset() ?: return this

    val text = String(this, charset).removePrefix("﻿")
    val adapted = if (charset == Charsets.UTF_8) text else text.replaceFirst(XML_ENCODING_REGEX, "$1$2UTF-8$2")

    return adapted.toByteArray(Charsets.UTF_8)
}

/** Return the charset of this content if it is not plain UTF-8 without byte order mark, or *null* otherwise. */
@Suppress("CyclomaticComplexMethod", "MagicNumber")
private fun ByteArray.detectCharset(): Charset? {
    fun at(index: Int): Int = if (index < size) this[index].toInt() and 0xFF else -1

    return when {
        at(0) == 0x00 && at(1) == 0x00 && at(2) == 0xFE && at(3) == 0xFF -> UTF_32BE
        at(0) == 0xFF && at(1) == 0xFE && at(2) == 0x00 && at(3) == 0x00 -> UTF_32LE
        at(0) == 0xEF && at(1) == 0xBB && at(2) == 0xBF -> Charsets.UTF_8
        at(0) == 0xFE && at(1) == 0xFF -> Charsets.UTF_16BE
        at(0) == 0xFF && at(1) == 0xFE -> Charsets.UTF_16LE

        // Without byte order mark, the first character of all supported formats is an ASCII character.
        at(0) == 0x00 && at(1) == 0x00 && at(2) == 0x00 && at(3) > 0 -> UTF_32BE
        at(0) > 0 && at(1) == 0x00 && at(2) == 0x00 && at(3) == 0x00 -> UTF_32LE
        at(0) == 0x00 && at(1) > 0 -> Charsets.UTF_16BE
        at(0) > 0 && at(1) == 0x00 -> Charsets.UTF_16LE

        else -> null
    }
}
