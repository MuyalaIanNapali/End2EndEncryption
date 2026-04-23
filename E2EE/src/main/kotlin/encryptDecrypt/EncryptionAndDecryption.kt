package org.example.encryptDecrypt

import jdk.javadoc.internal.doclets.formats.html.markup.HtmlStyle
import org.example.doubleRatchet.RatchetState
import org.example.doubleRatchet.RatchetStateHE
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

class EncryptionAndDecryption {


    /*

                    Encryption Logic


     */


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



    /*



                 Decryption Logic



     */

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



    fun ratchetReceiveKey(
        ratchetState: RatchetState,
        headerBytes: ByteArray
    ): ByteArray{
        val header = EncryptionAndDecryptionUtility().decodeHeader(headerBytes)

        val messageKey = EncryptionAndDecryptionUtility().trySkippedMessageKeys(
            ratchetState,
            header
        )

        if (messageKey != null){
            return messageKey
        }



        if(!header.dhPublic.encoded.contentEquals(ratchetState.DHr?.encoded)){
            EncryptionAndDecryptionUtility().skippedMessageKeys(
                ratchetState,
                header.PN
            )

            EncryptionAndDecryptionUtility().DHRatchet(
                ratchetState,
                header
            )
        }

        EncryptionAndDecryptionUtility().skippedMessageKeys(
            ratchetState,
            header.N
        )

        val (CKr,mk)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKr))

        ratchetState.CKr=CKr

        ratchetState.Nr +=1

        return mk
    }

    fun ratchetDecrypt(
        ratchetState: RatchetState,
        headerByte: ByteArray,
        ciphertext: ByteArray,
        AD: ByteArray
    ): String{

        val messageKey = ratchetReceiveKey(
            ratchetState,
            headerByte
        )

        return String(
            plainTextDecryption(
                messageKey,
                ciphertext,
                EncryptionAndDecryptionUtility().concat(
                    AD,
                    headerByte
                )
            )
        )
    }

    /*
            HEADER ENCRYPTION AND DECRYPTION LOGIC
     */

    fun headerEncryption(
        headerKey: ByteArray,
        plaintext: ByteArray
    ): ByteArray {

        val aesKeyEncrypt = SecretKeySpec(headerKey, "AES")

        val nonce= ByteArray(12)
        java.security.SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyEncrypt, spec)


        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }

    fun headerDecryption(
        headerKey: ByteArray,
        ciphertext: ByteArray
    ): HEADER {

        require(ciphertext.size >= 12) { "Ciphertext too short" }
        require(headerKey.isNotEmpty()){ "Header key must be present"}

        val nonce = ciphertext.copyOfRange(0, 12)

        val actualCiphertext = ciphertext.copyOfRange(12, ciphertext.size)

        val aesKey = SecretKeySpec(headerKey, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)

        return EncryptionAndDecryptionUtility().decodeHeader(
            cipher.doFinal(actualCiphertext)
        )
    }

    /*
        Ratchet Encryption with Header Encryption
     */

    fun ratchetEncryptHE(
        state: RatchetStateHE,
        plainText: String,
        associatedData: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val(CKs,mk) = KDFChain().kdfChainKey(requireNotNull(state.CKs))
        state.CKs=CKs

        val header = HEADER(
            state.DHs.public,
            state.PN,
            state.Ns
        )

        val encryptedHeader = headerEncryption(
            requireNotNull(state.HKs),
            EncryptionAndDecryptionUtility().encodeHeader(header)
        )

        state.Ns +=1

        return Pair(
            encryptedHeader,
            plainTextEncryption(
                mk,
                plainText.toByteArray(),
                EncryptionAndDecryptionUtility().concat(
                    associatedData,
                    encryptedHeader
                )
            )
        )
    }


    /*
        Ratchet Decryption with Header Decryption
     */


    fun ratchetDecryptHE(
        state: RatchetStateHE,
        encryptedHeader: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): String {
        val plaintext= EncryptionAndDecryptionUtility().trySkippedMessageKeysHE(
            state,encryptedHeader,
            ciphertext,
            associatedData
        )

        if (plaintext != null) {
            return String(plaintext)
        }

        val (header,dhRatchet)= decryptHeader(state,encryptedHeader)

        if (dhRatchet){
            skippedMessageKeysHE(state,header.PN)
            EncryptionAndDecryptionUtility().DHRatchetHE(state,header)
        }

        skippedMessageKeysHE(state,header.N)

        val(CKr,mk) = KDFChain().kdfChainKey(requireNotNull(state.CKr))

        state.CKr=CKr
        state.Nr +=1

        return String(
            plainTextDecryption(
                mk,
                ciphertext,
                EncryptionAndDecryptionUtility().concat(
                    associatedData,
                    encryptedHeader
                )
            )
        )
    }

    fun decryptHeader(
        state: RatchetStateHE,
        encryptedHeader: ByteArray
    ): Pair<HEADER, Boolean> {

        val hk = state.HKr
        if (hk != null) {
            try {
                val header = headerDecryption(hk, encryptedHeader)
                return Pair(header, false)
            } catch (e: Exception) {
                // authentication failed → try next key
            }
        }

        val nhk = state.NHKr
        if (nhk != null) {
            try {
                val header = headerDecryption(nhk, encryptedHeader)
                return Pair(header, true)
            } catch (e: Exception) {
                // authentication failed
            }
        }

        throw IllegalStateException("Header decryption failed")
    }

    fun skippedMessageKeysHE(
        state: RatchetStateHE,
        until : Int
    ){
        require(state.Nr+ state.MAX_SKIP >= until){
            "Error"
        }

        if(state.CKr != null){
            while (state.Nr < until){
                val (CKr,messageKey) = KDFChain().kdfChainKey(requireNotNull(state.CKr))

                state.CKr=CKr

                val key = Pair(state.HKr!!, state.Nr)
                state.MKSKIPPED[key] = messageKey

                state.Nr +=1
            }
        }
    }


}