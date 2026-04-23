package org.example.kdf

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HKDF {
    private const val HASH_ALGORITHM = "HmacSHA256"
    private const val HASH_LENGTH = 32

    private fun hmac(
        key: ByteArray,
        data: ByteArray
    ): ByteArray {

        val mac = Mac.getInstance(HASH_ALGORITHM)
        val keySpec = SecretKeySpec(key, HASH_ALGORITHM)

        mac.init(keySpec)
        return mac.doFinal(data)
    }

    fun extract(
        salt: ByteArray?,
        inputKeyMaterial : ByteArray
    ): ByteArray {

        val actualSalt = salt ?: ByteArray(HASH_LENGTH){0}
        return hmac(actualSalt, inputKeyMaterial)

    }

    fun expand(
        pseudoRandomKey: ByteArray,
        info:ByteArray ,
        outputLength :Int
    ): ByteArray {

        require(outputLength > 0 && outputLength <= 255 * HASH_LENGTH){
            "outputLength must be greater than zero and less than $outputLength "
        }
        val numberOfIterations = (outputLength + HASH_LENGTH - 1) / HASH_LENGTH

        var numberOfOutputBlocks = ByteArray(0)
        val result = ByteArray(outputLength)
        var offset = 0

        for (i in 1..numberOfIterations) {
            val input = numberOfOutputBlocks + info + byteArrayOf((i and 0xFF).toByte())
            numberOfOutputBlocks = hmac(pseudoRandomKey, input)

            val remaining = outputLength - offset
            val copyLen = minOf(HASH_LENGTH, remaining)

            System.arraycopy(
                numberOfOutputBlocks,
                0,
                result,
                offset,
                copyLen
            )

            offset += copyLen

        }

        return result

    }

    fun rootHKDF(
        inputKeyMaterial: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        outputLength: Int
    ): Pair<ByteArray, ByteArray> {

        val pseudoRandomKey = extract(salt, inputKeyMaterial)
        val output= expand(pseudoRandomKey, info, outputLength)

        val rootKey = output.copyOfRange(0,32)
        val chainKey = output.copyOfRange(32,64)

        return Pair(rootKey,chainKey)

    }

    fun chainHKDF(ck: ByteArray): Pair<ByteArray, ByteArray>{

        val chainKey = hmac(ck, byteArrayOf(0x01))
        val mk    = hmac(ck, byteArrayOf(0x02))
        return Pair(chainKey, mk)

    }

    fun rootHEHKDF(
        inputKeyMaterial: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        outputLength: Int
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val pseudoRandomKey = extract(salt, inputKeyMaterial)
        val output= expand(pseudoRandomKey, info, outputLength)


        val rootKey = output.copyOfRange(0,32)
        val chainKey = output.copyOfRange(32,64)
        val headerKey = output.copyOfRange(64,96)

        return Triple(rootKey, chainKey, headerKey)

    }
}