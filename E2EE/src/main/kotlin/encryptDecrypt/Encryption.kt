package org.example.encryptDecrypt

import org.example.doubleRatchet.RatchetState
import org.example.kdf.KDFChain
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


    fun ratchetSendKey(ratchetState: RatchetState): Pair<Int, ByteArray>{
        val (newChainKey,messageKey)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKs))

        ratchetState.CKs=newChainKey

        val Ns = ratchetState.Ns
        ratchetState.Ns +=1

        return Pair(Ns,messageKey)


    }
    fun ratchetEncrypt(
        ratchetState: RatchetState,
        plainText : String,
        AD : ByteArray
    ): Pair<ByteArray, ByteArray> {

        val(Ns,messageKey) = ratchetSendKey(ratchetState)

        val header = HEADER(ratchetState.DHs.public, ratchetState.PN,Ns)

        val headerBytes = EncryptionAndDecryptionUtility().encodeHeader(header)

        return Pair(
            headerBytes,
            plainTextEncryption(
                messageKey,plainText.toByteArray(),
                EncryptionAndDecryptionUtility().concat(
                    AD,
                    headerBytes
                )
            )
        )
    }


}