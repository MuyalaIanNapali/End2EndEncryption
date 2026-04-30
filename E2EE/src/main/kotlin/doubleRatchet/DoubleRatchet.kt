package doubleRatchet

import kdf.KDFChain
import encryptDecrypt.EllipticCurveDiffieHellman
import java.security.KeyPair
import java.security.PublicKey

class DoubleRatchet(
    private val kdfChain: KDFChain,
    private val ecdh: EllipticCurveDiffieHellman
) {

    fun ratchetInitAliceHE(
        SK: ByteArray,
        bobPublicKey: PublicKey,
        sharedHKa: ByteArray,
        sharedNHKb: ByteArray
    ): RatchetStateHE {
        val DHs = ecdh.generateEllipticCurveKeyPair()

        val(RK,CKs,NHKs)=kdfChain.kdfRootKey(
            SK,
            ecdh.performDH(
                DHs.private,
                bobPublicKey
            )
        )

        return RatchetStateHE(
            DHs = DHs,
            DHr = bobPublicKey,
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

    fun ratchetInitBobHE(
        SK: ByteArray,
        bobKeyPair: KeyPair,
        sharedHKa: ByteArray,
        sharedNHKb: ByteArray
    ): RatchetStateHE{
        return RatchetStateHE(
            DHs = bobKeyPair,
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