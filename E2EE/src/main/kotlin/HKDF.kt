package org.example

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HKDF {
    private const val HASH_ALGORITHM = "HmacSHA256"
    private const val HASH_LENGTH = 32

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HASH_ALGORITHM)
        val keySpec = SecretKeySpec(key, HASH_ALGORITHM)

        mac.init(keySpec)
        return mac.doFinal(data)
    }

    fun extract(salt: ByteArray?,inputKeyMaterial : ByteArray): ByteArray {
        val actualSalt = salt ?: ByteArray(HASH_LENGTH){0}
        return hmac(actualSalt, inputKeyMaterial)
    }

    fun expand(pseudoRandomKey: ByteArray,info:ByteArray ,outputLength :Int): ByteArray {
        val numberOfIterations = (outputLength + HASH_LENGTH - 1) / HASH_LENGTH

        var numberOfOutputBlocks = ByteArray(0)
        val result = ByteArray(outputLength)
        var offset = 0

        for (i in 1..numberOfIterations) {
            val input = numberOfOutputBlocks + info + byteArrayOf(i.toByte())
            numberOfOutputBlocks = hmac(pseudoRandomKey, input)

            val remaining = outputLength - offset
            val copyLen = minOf(HASH_LENGTH, remaining)

            System.arraycopy(numberOfOutputBlocks, 0, result, offset, copyLen)
            offset += copyLen
        }
        return result
    }

    fun deriveKey(
        inputKeyMaterial: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        val pseudoRandomKey = extract(salt, inputKeyMaterial)
        return expand(pseudoRandomKey, info, outputLength)
    }
}