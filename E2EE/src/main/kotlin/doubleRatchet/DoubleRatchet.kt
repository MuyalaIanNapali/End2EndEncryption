package org.example.doubleRatchet

import org.example.encryptDecrypt.EllipticCurveDiffieHellman
import org.example.kdf.KDFChain
import java.security.KeyPair
import java.security.PublicKey

class DoubleRatchet(
    private val kdfChain: KDFChain,
    private val ecdh: EllipticCurveDiffieHellman
) {

    fun ratchetInitAlice(
        SK: ByteArray,
        bobPublicKey: PublicKey
    ): RatchetState {

        val DHs = ecdh.generateEllipticCurveKeyPair()

        val (RK, CKs) = kdfChain.kdfRootKey(SK, ecdh.performDH(DHs, bobPublicKey))

        return RatchetState(
            DHs = DHs,
            DHr = bobPublicKey,
            RK = RK,
            CKs = CKs,
            CKr = null,
            Ns = 0,
            Nr = 0,
            PN = 0
        )
    }



    fun ratchetInitBob(SK: ByteArray,bobKeyPair : KeyPair): RatchetState {
        return RatchetState(
            DHs = bobKeyPair,
            DHr = null,
            RK = SK,
            CKs = null,
            CKr = null,
            Ns = 0,
            Nr = 0,
            PN = 0
        )
    }


    fun ratchetInitAliceHE(
        SK: ByteArray,
        bobPublicKey: PublicKey,
        sharedHKa: ByteArray,
        sharedNHKb: ByteArray
    ): RatchetStateHE{
        val DHs = ecdh.generateEllipticCurveKeyPair()

        val(RK,CKs,NHKs)=kdfChain.kdfRootKeyHeaderEncryption(
            SK,
            ecdh.performDH(
                DHs,
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