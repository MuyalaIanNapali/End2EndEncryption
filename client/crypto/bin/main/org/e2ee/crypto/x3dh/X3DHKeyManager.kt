package org.e2ee.crypto.x3dh

import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import java.security.KeyPair
import java.security.PrivateKey

class X3DHKeyManager (

    private val ecc: EllipticCurveDiffieHellman,
    private val sig : SignatureHelper
) {

    fun initIdentityKeys(): Pair<KeyPair, KeyPair> {
        return Pair(
            ecc.generateEllipticCurveKeyPair(),
            sig.generateSigningKeyPair()
        )
    }

    fun generateSignedPreKey(
        signingKey: PrivateKey,
    ):Pair<Pair<ByteArray,ByteArray>, ByteArray> {
        val signedPreKeyPair = ecc.generateEllipticCurveKeyPair()

        val signature = sig.signMessage(
            signedPreKeyPair.public.encoded,
            signingKey
        )

        return Pair(
            Pair(
                signedPreKeyPair.public.encoded,
                signedPreKeyPair.private.encoded
            ),
            signature,
        )
    }


}