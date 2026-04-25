package encryptDecrypt

import doubleRatchet.RatchetStateHE
import kdf.KDFChain
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class HeaderDecryption {
    private val util = EncryptionAndDecryptionUtility()

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

        return util.decodeHeader(
            cipher.doFinal(actualCiphertext)
        )
    }



    fun ratchetDecryptHE(
        state: RatchetStateHE,
        encryptedHeader: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): String {
        val plaintext= util.trySkippedMessageKeysHE(
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
            Decryption().plainTextDecryption(
                mk,
                ciphertext,
                util.concat(
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