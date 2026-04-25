package encryptDecrypt

import doubleRatchet.RatchetState
import doubleRatchet.RatchetStateHE
import kdf.KDFChain
import java.nio.ByteBuffer
import java.security.KeyFactory
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



    fun decodeHeader(bytes: ByteArray): HEADER {
        val buffer = ByteBuffer.wrap(bytes)

        val keyLen = buffer.getInt()
        require(keyLen > 0 && keyLen <= bytes.size - 12) { "Invalid public key length" }

        val publicKeyBytes = ByteArray(keyLen)
        buffer.get(publicKeyBytes)

        val pn = buffer.getInt()
        val n = buffer.getInt()

        val keyFactory = KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

        return HEADER(
            publicKey,
            pn,
            n
        )
    }


    fun trySkippedMessageKeys(
        ratchetState: RatchetState,
        header: HEADER
    ): ByteArray? {


        val key = Pair(header.dhPublic,header.N)

        return ratchetState.MKSKIPPED.remove(key)
    }

    fun skippedMessageKeys(ratchetState: RatchetState, until: Int){
        require(ratchetState.Nr+ ratchetState.MAX_SKIP >= until){
            "Error"
        }

        if(ratchetState.CKr != null){
            while (ratchetState.Nr < until){
                val (CKr,messageKey) = KDFChain().kdfChainKey(requireNotNull(ratchetState.CKr))

                ratchetState.CKr=CKr

                val key = Pair(ratchetState.DHr!!, ratchetState.Nr)
                ratchetState.MKSKIPPED[key] = messageKey

                ratchetState.Nr +=1
            }
        }
    }


    fun DHRatchet(ratchetState: RatchetState, header: HEADER){
        ratchetState.PN = ratchetState.Ns
        ratchetState.Ns = 0
        ratchetState.Nr = 0
        ratchetState.DHr=header.dhPublic

        val (rK,cKr)= KDFChain().kdfRootKey(
            ratchetState.RK,
            EllipticCurveDiffieHellman().performDH(
                ratchetState.DHs,
                requireNotNull(ratchetState.DHr
                )
            )
        )
        ratchetState.RK=rK
        ratchetState.CKr=cKr
        ratchetState.DHs= EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()

        val (rK2,cKs)= KDFChain().kdfRootKey(
            ratchetState.RK,
            EllipticCurveDiffieHellman().performDH(
                ratchetState.DHs,
                requireNotNull(ratchetState.DHr
                )
            )
        )
        ratchetState.RK=rK2
        ratchetState.CKs=cKs

    }

    fun trySkippedMessageKeysHE(
        state: RatchetStateHE,
        encryptedHeader: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray
    ): ByteArray? {

        for ((key, mk) in state.MKSKIPPED.toMap()) {
            val (hk, n) = key

            try {
                // decrypt header bytes
                val header =    HeaderDecryption().headerDecryption(
                    hk,
                    encryptedHeader
                )


                if (header.N == n) {
                    state.MKSKIPPED.remove(key)

                    val fullAD = EncryptionAndDecryptionUtility().concat(
                        associatedData,
                        encryptedHeader
                    )

                    return Decryption().plainTextDecryption(
                        mk,
                        ciphertext,
                        fullAD
                    )
                }
            } catch (e: Exception) {
                // wrong key -> ignore and continue trying others
                continue
            }
        }

        return null
    }


    fun DHRatchetHE(
        state: RatchetStateHE,
        header: HEADER
    ){
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.HKs = state.NHKs
        state.HKr = state.NHKr
        state.DHr=header.dhPublic

        val(RK,CKr,NHKr)= KDFChain().kdfRootKeyHeaderEncryption(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs,
                requireNotNull(state.DHr)
            )
        )
        state.RK=RK
        state.CKr= CKr
        state.NHKr= NHKr

        state.DHs= EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()

        val(RK2,CKs,NHKs)= KDFChain().kdfRootKeyHeaderEncryption(
            state.RK,
            EllipticCurveDiffieHellman().performDH(
                state.DHs,
                requireNotNull(state.DHr)
            )
        )

        state.RK=RK2
        state.CKs= CKs
        state.NHKs= NHKs

    }


}