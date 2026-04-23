package org.example.encryptDecrypt

import org.example.doubleRatchet.RatchetStateHE
import org.example.kdf.KDFChain
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