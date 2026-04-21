package org.example

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

        val dhOutput = ecdh.performDH(DHs, bobPublicKey)

        val (RK, CKs) = kdfChain.kdfRootKey(SK, dhOutput)

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


}