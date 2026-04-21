package org.example

import java.nio.ByteBuffer

class EncryptionAndDecryptionUtility {
    fun concat(ad: ByteArray, header: HEADER): ByteArray {
        val adLength = ad.size

        val header = encodeHeader(header)

        // 4 bytes to store length (Int)
        val result = ByteArray(4 + adLength + header.size)

        // Write length (big-endian)
        result[0] = (adLength shr 24).toByte()
        result[1] = (adLength shr 16).toByte()
        result[2] = (adLength shr 8).toByte()
        result[3] = adLength.toByte()

        // Copy ad
        System.arraycopy(ad, 0, result, 4, adLength)

        // Copy header
        System.arraycopy(header, 0, result, 4 + adLength, header.size)

        return result
    }


    fun encodeHeader(header: HEADER): ByteArray {
        val publicKeyBytes = header.dhPublic.encoded

        val buffer = ByteBuffer.allocate(
            4 + publicKeyBytes.size + 4 + 4
        )

        buffer.putInt(publicKeyBytes.size)
        buffer.put(publicKeyBytes)
        buffer.putInt(header.PN)
        buffer.putInt(header.Ns)

        return buffer.array()
    }
}