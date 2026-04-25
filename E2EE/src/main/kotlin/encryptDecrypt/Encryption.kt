package encryptDecrypt

import doubleRatchet.RatchetState
import kdf.KDFChain
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.PublicKey

data class HEADER(
    var dhPublic: PublicKey,
    var PN: Int,
    var N: Int
)

class Encryption {
    private val util = EncryptionAndDecryptionUtility()

    fun plainTextEncryption(
        messageKey: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray
    ): ByteArray {

        val aesKeyEncrypt = SecretKeySpec(messageKey, "AES")
        val nonceFull = MessageDigest.getInstance("SHA-256").digest(messageKey)

        val nonce = nonceFull.copyOfRange(0,12)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyEncrypt, spec)
        cipher.updateAAD(associatedData)

        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }

}