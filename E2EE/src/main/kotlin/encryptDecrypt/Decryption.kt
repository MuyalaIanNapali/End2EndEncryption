package encryptDecrypt

import doubleRatchet.RatchetState
import doubleRatchet.RatchetStateHE
import doubleRatchet.deepCopy
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
        ratchetState: RatchetStateHE
    ): Pair<RatchetStateHE, ByteArray>{
         var ratchetState = ratchetState.deepCopy()
        //val header = EncryptionAndDecryptionUtility().decodeHeader(headerBytes)

        val (CKr,mk)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKr))


        return Pair(
            ratchetState.copy(
                CKr = CKr,
                Nr = ratchetState.Nr + 1
            ),
            mk
        )
    }



    fun decryptPreKeyMessage(
        ratchetState: RatchetStateHE,
        ciphertext: ByteArray,
        AD: ByteArray
    ): Pair<RatchetStateHE,String>{

        var newState = ratchetState.deepCopy()



        val (newState1,messageKey) = ratchetReceiveKey(
            newState
        )

        newState = newState1

        return Pair(
            newState,
            String(
                plainTextDecryption(
                    messageKey,
                    ciphertext,
                    AD
                )
            )
        )
    }

}