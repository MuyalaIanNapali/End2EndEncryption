package org.example

import java.security.KeyPair
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class HEADER(
    var DHs: KeyPair,
    var PN: Int,
    var Ns: Int
)

class EncryptionAndDecryption {
    fun encrypt(
        messageKey: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray
    ): ByteArray {
        val aesKey = SecretKeySpec(messageKey, "AES")
        val nonceFull = MessageDigest.getInstance("SHA-256").digest(messageKey)

        val nonce = nonceFull.copyOfRange(0,12)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec)
        cipher.updateAAD(associatedData)

        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }
}