package x3dh

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class SignatureHelper {
    fun generateSigningKeyPair(): KeyPair {
        val keygen = KeyPairGenerator.getInstance("Ed25519")
        return keygen.generateKeyPair()
    }

    fun signMessage(
        message: ByteArray,
        privateKey: PrivateKey
    ): ByteArray {
        val signature = Signature.getInstance("Ed25519")
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    fun verifySignature(
        message: ByteArray,
        signatureBytes: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        val signature = Signature.getInstance("Ed25519")
        signature.initVerify(publicKey)
        signature.update(message)
        return signature.verify(signatureBytes)
    }

    fun decodeEdPublicKey(publicKeyBytes: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("Ed25519")
        return keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
    }

}