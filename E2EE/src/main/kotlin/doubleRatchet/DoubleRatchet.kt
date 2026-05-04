package doubleRatchet

import kdf.KDFChain
import encryptDecrypt.EllipticCurveDiffieHellman
import java.security.KeyPair
import java.security.PublicKey

class DoubleRatchet(
    private val kdfChain: KDFChain,
    private val ecdh: EllipticCurveDiffieHellman
) {

    fun ratchetInitSenderHE(
        SK: ByteArray,
        recieverPublicKey: PublicKey,
        sharedHKa: ByteArray,
        sharedNHKb: ByteArray?
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
            HKs = sharedHKa,
            HKr = null,
            NHKs = NHKs,
            NHKr = sharedNHKb
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