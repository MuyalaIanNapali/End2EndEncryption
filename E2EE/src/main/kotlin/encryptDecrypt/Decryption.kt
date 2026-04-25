package encryptDecrypt

import doubleRatchet.RatchetState
import kdf.KDFChain
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class Decryption {

    fun plainTextDecryption(
        messageKey: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): ByteArray {

        require(ciphertext.size >= 12) { "Ciphertext too short" }

        val nonce = ciphertext.copyOfRange(0, 12)
        val actualCiphertext = ciphertext.copyOfRange(12, ciphertext.size)

        val aesKey = SecretKeySpec(messageKey, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)

        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)
        cipher.updateAAD(associatedData)

        return cipher.doFinal(actualCiphertext)
    }

}