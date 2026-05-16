package org.e2ee.crypto.doubleRatchet


import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import org.e2ee.crypto.kdf.KDFChain
import java.security.KeyPair
import java.security.PublicKey

internal class DoubleRatchet(
    private val kdfChain: KDFChain,
    private val ecdh: EllipticCurveDiffieHellman
) {

    fun ratchetInitSenderHE(
        SK: ByteArray,
        recieverPublicKey: PublicKey,
        sharedHKs: ByteArray,
        sharedNHKr: ByteArray?
    ): RatchetStateHE {
        val DHs = ecdh.generateEllipticCurveKeyPair()

        val(RK,CKs,NHKs)=kdfChain.kdfRootKey(
            SK,
            ecdh.performDH(
                DHs.private,
                recieverPublicKey
            )
        )

        return RatchetStateHE(
            DHs = DHs,
            DHr = recieverPublicKey,
            RK = RK,
            CKs = CKs,
            CKr = null,
            Ns = 0,
            Nr = 0,
            PN = 0,
            HKs = sharedHKs,
            HKr = null,
            NHKs = NHKs,
            NHKr = sharedNHKr
        )
    }

    fun ratchetInitReceiverHE(
        SK: ByteArray,
        userKeyPair: KeyPair,
        sharedHKa: ByteArray,
        sharedNHKb: ByteArray
    ): RatchetStateHE{
        return RatchetStateHE(
            DHs = userKeyPair,
            DHr = null,
            RK=SK,
            CKs = null,
            CKr = null,
            Ns = 0,
            Nr = 0,
            PN = 0,
            HKs=null,
            NHKs = sharedNHKb,
            NHKr = sharedHKa,
            HKr = null
        )
    }


}