package encryptDecrypt

import doubleRatchet.RatchetStateHE
import doubleRatchet.deepCopy
import kdf.KDFChain
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class HeaderEncryption {

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



    fun ratchetEncryptHE(
        ratchetState: RatchetStateHE,
        plainText: String,
        associatedData: ByteArray
    ): Triple<RatchetStateHE,ByteArray, ByteArray> {
        val state = ratchetState.deepCopy()
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

        return Triple(
            state.copy(
                Ns = state.Ns + 1
            ),
            encryptedHeader,
            Encryption().plainTextEncryption(
                mk,
                plainText.toByteArray(),
                EncryptionAndDecryptionUtility().concat(
                    associatedData,
                    encryptedHeader
                )
            )
        )
    }

}