package org.e2ee.crypto.x3dh

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

internal class SignatureHelper {

    init {
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    fun generateSigningKeyPair(): KeyPair {

        val keygen = KeyPairGenerator.getInstance("Ed25519", "BC")

        val keyPair = keygen.generateKeyPair()

        return keyPair
    }

    fun signMessage(
        message: ByteArray,
        privateKey: PrivateKey
    ): ByteArray {
        val signature = Signature.getInstance("Ed25519", "BC")
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    fun verifySignature(
        message: ByteArray,
        signatureBytes: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        val signature = Signature.getInstance("Ed25519", "BC")
        signature.initVerify(publicKey)
        signature.update(message)
        return signature.verify(signatureBytes)
    }

    fun decodeEdPublicKey(publicKeyBytes: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
        return keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
    }

    fun decodeEdPrivateKey(privateKeyBytes: ByteArray): PrivateKey {
        val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
    }
}