package org.e2ee.crypto.x3dh


import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import java.security.KeyPair
import java.security.PrivateKey

class X3DHKeyManager (

    private val ecc: EllipticCurveDiffieHellman,
    private val sig : SignatureHelper
    ) {

    val opkStore = OPKStore()

    lateinit var identityKeyPair: KeyPair
    lateinit var signedPreKeyPair: KeyPair
    lateinit var identitySigningKey: KeyPair

    fun initIdentityKeys() {
        identityKeyPair = ecc.generateEllipticCurveKeyPair()
        identitySigningKey = sig.generateSigningKeyPair()
    }

    fun generateSignedPreKey() {
        signedPreKeyPair = ecc.generateEllipticCurveKeyPair()
    }

    fun generateOPK(count: Int, store: OPKStore): Map<String, ByteArray> {
        return (0 until count).associate { i ->
            val kp = ecc.generateEllipticCurveKeyPair()
            val id = "OPK$i"

            store.add(id, kp.private)

            id to kp.public.encoded
        }
    }

    fun removeOPK(id: String) {
        opkStore.consume(id)
    }

    fun getOPKPrivate(id: String) : PrivateKey? {
        return opkStore.get(id)
    }


}