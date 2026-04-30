package encryptDecrypt

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

class EllipticCurveDiffieHellman {

    fun generateEllipticCurveKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("X25519")
        return keyGen.generateKeyPair()
    }

    fun performDH(
        privateKey: PrivateKey,
        publicKey: PublicKey
    ): ByteArray {

        val keyAgreement = KeyAgreement.getInstance("X25519")

        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)

        return keyAgreement.generateSecret()
    }
}