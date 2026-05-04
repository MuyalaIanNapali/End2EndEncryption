package encryptDecrypt

import doubleRatchet.RatchetStateHE
import doubleRatchet.deepCopy
import kdf.KDFChain
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

class EncryptionAndDecryptionUtility {
    fun concat(ad: ByteArray, header: ByteArray): ByteArray {
        val adLength = ad.size

        // 4 bytes to store length (Int)
        val result = ByteArray(4 + adLength + header.size)

        // Write length (big-endian)
        result[0] = (adLength shr 24).toByte()
        result[1] = (adLength shr 16).toByte()
        result[2] = (adLength shr 8).toByte()
        result[3] = adLength.toByte()

        // Copy ad
        System.arraycopy(ad, 0, result, 4, adLength)

        // Copy header
        System.arraycopy(header, 0, result, 4 + adLength, header.size)

        return result
    }


    fun encodeHeader(header: HEADER): ByteArray {
        val publicKeyBytes = header.dhPublic.encoded

        val buffer = ByteBuffer.allocate(
            4 + publicKeyBytes.size + 4 + 4
        )

        buffer.putInt(publicKeyBytes.size)
        buffer.put(publicKeyBytes)
        buffer.putInt(header.PN)
        buffer.putInt(header.N)

        return buffer.array()
    }

    fun decodePublicKey(publicKeyBytes: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("X25519")
        return keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
    }

    fun decodeHeader(bytes: ByteArray): HEADER {
        val buffer = ByteBuffer.wrap(bytes)

        val keyLen = buffer.getInt()
        require(keyLen > 0 && keyLen <= bytes.size - 12) { "Invalid public key length" }

        val publicKeyBytes = ByteArray(keyLen)
        buffer.get(publicKeyBytes)

        val pn = buffer.getInt()
        val n = buffer.getInt()

        val publicKey = decodePublicKey(publicKeyBytes)

        return HEADER(
            publicKey,
            pn,
            n
        )
    }


    fun trySkippedMessageKeysHE(
        ratchetState: RatchetStateHE,
        encryptedHeader: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): Pair<RatchetStateHE,ByteArray?> {
        val state = ratchetState.deepCopy()

        for ((key, mk) in state.MKSKIPPED.toMap()) {
            val (hk, n) = key

            try {
                // decrypt header bytes
                val header =    HeaderDecryption().headerDecryption(
                    hk,
                    encryptedHeader
                )


                if (header.N == n) {
                    val newSkipped = state.MKSKIPPED.toMutableMap()
                    newSkipped.remove(key)

                    val fullAD = EncryptionAndDecryptionUtility().concat(
                        associatedData,
                        encryptedHeader
                    )

                    return Pair(
                        state.copy(
                            MKSKIPPED = newSkipped
                        ),
                        Decryption().plainTextDecryption(
                            mk,
                            ciphertext,
                            fullAD
                        )
                    )

                }
            } catch (e: Exception) {
                // wrong key -> ignore and continue trying others
                continue
            }
        }

        return Pair(state,null)
    }


    fun DHRatchetHE(
        ratchetState: RatchetStateHE,
        header: HEADER
    ):RatchetStateHE {
        val state =ratchetState.deepCopy()

        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.HKs = state.NHKs
        state.HKr = state.NHKr
        state.DHr=header.dhPublic

        val(RK,CKr,NHKr)= KDFChain().kdfRootKey(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs.private,
                requireNotNull(state.DHr)
            )
        )
        state.RK=RK
        state.CKr= CKr
        state.NHKr= NHKr

        state.DHs= EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()

        val(RK2,CKs,NHKs)= KDFChain().kdfRootKey(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs.private,
                requireNotNull(state.DHr)
            )
        )

        state.RK=RK2
        state.CKs= CKs
        state.NHKs= NHKs

        return state

    }


    fun DHRatchetPreKeyMessage(
        ratchetState: RatchetStateHE,
        DHs: ByteArray,
    ):RatchetStateHE {
        val state =ratchetState.deepCopy()

        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.HKs = state.NHKs
        state.HKr = state.NHKr
        state.DHr= EncryptionAndDecryptionUtility().decodePublicKey(DHs)

        val(RK,CKr,NHKr)= KDFChain().kdfRootKey(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs.private,
                requireNotNull(state.DHr)
            )
        )
        state.RK=RK
        state.CKr= CKr
        state.NHKr= NHKr

        state.DHs= EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()

        val(RK2,CKs,NHKs)= KDFChain().kdfRootKey(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs.private,
                requireNotNull(state.DHr)
            )
        )

        state.RK=RK2
        state.CKs= CKs
        state.NHKs= NHKs

        return state

    }



}