package org.example

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

class EncryptionAndDecryption {


    /*

                    Encryption Logic


     */


    fun encrypt(
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
    fun ratchetEncrypt(ratchetState: RatchetState,plainText : String ,AD : ByteArray): Pair<HEADER, ByteArray> {
        val(Ns,messageKey) = ratchetSendKey(ratchetState)

        val header = HEADER(ratchetState.DHs.public, ratchetState.PN,Ns)

        val headerBytes = EncryptionAndDecryptionUtility().encodeHeader(header)

        return Pair(
            header,
            encrypt(messageKey,plainText.toByteArray(), EncryptionAndDecryptionUtility().concat(AD,headerBytes))
        )
    }



    /*



                 Decryption Logic



     */

    fun decrypt(
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



    fun ratchetReceiveKey(ratchetState: RatchetState, header: HEADER): ByteArray{
        val messageKey = EncryptionAndDecryptionUtility().trySkippedMessageKeys(ratchetState,header)

        if (messageKey != null){
            return messageKey
        }

        if(header.dhPublic != ratchetState.DHr){
            EncryptionAndDecryptionUtility().skippedMessageKeys(ratchetState,header.PN)

            EncryptionAndDecryptionUtility().DHRatchet(ratchetState,header)
        }

        EncryptionAndDecryptionUtility().skippedMessageKeys(ratchetState,header.N)

        val (CKr,mk)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKr))

        ratchetState.CKr=CKr

        ratchetState.Nr +=1

        return mk
    }

    fun ratchetDecrypt(ratchetState: RatchetState,header: HEADER,ciphertext: ByteArray,AD: ByteArray): ByteArray{
        val messageKey = ratchetReceiveKey(ratchetState,header)

        val headerByte = EncryptionAndDecryptionUtility().encodeHeader(header)

        return decrypt(messageKey,ciphertext, EncryptionAndDecryptionUtility().concat(AD,headerByte))
    }
}