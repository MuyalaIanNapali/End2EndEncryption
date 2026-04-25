package encryptDecrypt

import doubleRatchet.RatchetStateHE
import doubleRatchet.deepCopy
import kdf.KDFChain
import javax.crypto.AEADBadTagException
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
        ratchetState: RatchetStateHE,
        encryptedHeader: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): Pair<RatchetStateHE, String> {
        var state = ratchetState.deepCopy()

        val (newSkippedState,plaintext)= util.trySkippedMessageKeysHE(
            state,
            encryptedHeader,
            ciphertext,
            associatedData
        )

        state = newSkippedState


        if (plaintext != null) {
            return Pair(
                state,
                String(plaintext)
            )
        }

        val (header,dhRatchet)= decryptHeader(state,encryptedHeader)

        if (dhRatchet){
            val newSkippedState = skippedMessageKeysHE(state,header.PN)
            state = newSkippedState

            val dhRatchetState = EncryptionAndDecryptionUtility().DHRatchetHE(state,header)
            state = dhRatchetState
        }

        val newSkippedState2 = skippedMessageKeysHE(state,header.N)
        state = newSkippedState2

        val(CKr,mk) = KDFChain().kdfChainKey(requireNotNull(state.CKr))


        return Pair(
            state.copy(
                CKr = CKr,
                Nr = state.Nr + 1
            ),
            String(Decryption().plainTextDecryption(
                mk,
                ciphertext,
                util.concat(
                    associatedData,
                    encryptedHeader
                )
            ))
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
            } catch (e : AEADBadTagException) {
                // authentication failed
            }
        }

        throw IllegalStateException("Header decryption failed")
    }

    fun skippedMessageKeysHE(
        state: RatchetStateHE,
        until : Int
    ): RatchetStateHE {

        require(until <= state.Nr + state.MAX_SKIP){
            "Too many skipped messages"
        }

        var CKr = state.CKr
        var Nr = state.Nr
        val newSkipped = state.MKSKIPPED.toMutableMap()

        if(CKr != null){

            val HKr = requireNotNull(state.HKr) {
                "HKr must not be null when skipping keys"
            }

            while (Nr < until){
                val (chainKey,messageKey) = KDFChain().kdfChainKey(requireNotNull(CKr))

                CKr = chainKey

                val key = Pair(HKr, Nr)
                newSkipped[key] = messageKey

                Nr +=1
            }
        }

        return state.copy(
            CKr = CKr,
            Nr = Nr,
            MKSKIPPED = newSkipped
        )
    }


}