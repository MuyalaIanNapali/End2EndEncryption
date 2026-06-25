package org.e2ee.crypto.backup.shamirSecretSharing

import java.math.BigInteger

object ByteUtils {

    fun byteArrayToBigInteger(bytes: ByteArray): BigInteger {
        return BigInteger(1, bytes)
    }

    fun bigIntegerToByteArray(
        value: BigInteger,
        size: Int = 32
    ): ByteArray {

        val src = value.toByteArray()

        return when {
            src.size == size -> src

            src.size < size -> {
                ByteArray(size - src.size) + src
            }

            else -> {
                src.copyOfRange(src.size - size, src.size)
            }
        }
    }
}