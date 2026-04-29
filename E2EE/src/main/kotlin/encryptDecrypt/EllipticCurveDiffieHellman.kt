package encryptDecrypt

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import javax.crypto.KeyAgreement

class EllipticCurveDiffieHellman {

    fun generateEllipticCurveKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("X25519")
        return keyGen.generateKeyPair()
    }

    fun performDH(
        dhPair: KeyPair,
        publicKey: PublicKey
    ): ByteArray {

        val keyAgreement = KeyAgreement.getInstance("X25519")

        keyAgreement.init(dhPair.private)
        keyAgreement.doPhase(publicKey, true)

        return keyAgreement.generateSecret()
    }
}