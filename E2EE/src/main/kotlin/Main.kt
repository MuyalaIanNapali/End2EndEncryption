package org.example

import java.util.*

object CryptoUtils {
    fun b64(data: ByteArray): String =
        Base64.getEncoder().encodeToString(data)
}

fun main() {
    val ecdh = EllipticCurveDiffieHellman()
    val kdf = KDFChain() // your implementation

    val doubleRatchet = DoubleRatchet(kdf, ecdh)

    val aliceKeyPair = EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()
    val bobKeyPair = EllipticCurveDiffieHellman().generateEllipticCurveKeyPair()

    val aliceSecretKey = EllipticCurveDiffieHellman().performDH(aliceKeyPair.private, bobKeyPair.public)


    val aliceRatchetState = doubleRatchet.ratchetInitAlice(aliceSecretKey, bobKeyPair.public)

    println(aliceRatchetState)
}