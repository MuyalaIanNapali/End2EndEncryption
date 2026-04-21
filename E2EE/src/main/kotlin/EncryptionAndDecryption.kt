package org.example

import java.security.KeyPair
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.security.PublicKey

data class HEADER(
    var dhPublic: PublicKey,
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
    fun ratchetSendKey(ratchetState: RatchetState): Pair<Int, ByteArray>{
        val (newChainKey,messageKey)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKs))

        ratchetState.CKs=newChainKey

        val Ns = ratchetState.Ns
        ratchetState.Ns +=1

        return Pair(Ns,messageKey)


    }
    fun ratchetEncrypt(ratchetState: RatchetState,plainText : String ,AD : ByteArray): Pair<HEADER, ByteArray> {
        val(Ns,messageKey) = ratchetSendKey(ratchetState)

        val header = HEADER(ratchetState.DHs.public, ratchetState.PN,Ns)



        return Pair(
            header,
            encrypt(messageKey,plainText.toByteArray(), EncryptionAndDecryptionUtility().concat(AD,header))
        )
    }
}