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

}