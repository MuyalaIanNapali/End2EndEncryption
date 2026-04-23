package org.example

import org.example.doubleRatchet.DoubleRatchet
import org.example.encryptDecrypt.EllipticCurveDiffieHellman
import org.example.encryptDecrypt.EncryptionAndDecryption
import org.example.encryptDecrypt.HEADER
import org.example.kdf.KDFChain
import java.util.*

object CryptoUtils {
    fun b64(data: ByteArray): String =
        Base64.getEncoder().encodeToString(data)
}
/*
fun main() {
    val ecdh = EllipticCurveDiffieHellman()
    val kdf = KDFChain()
    val doubleRatchet = DoubleRatchet(kdf, ecdh)
    val crypto = EncryptionAndDecryption()

    val AD = "associated-data".toByteArray()

    // Bob has a long-term ratchet kq eypair (initial public key Alice knows)
    val bobKeyPair = ecdh.generateEllipticCurveKeyPair()

    // SK must be a shared secret from some handshake (simulate using ECDH here)
    val handshakeAliceKeyPair = ecdh.generateEllipticCurveKeyPair()
    val handshakeBobKeyPair = ecdh.generateEllipticCurveKeyPair()
    val SK_alice = ecdh.performDH(handshakeAliceKeyPair, handshakeBobKeyPair.public)
    val SK_bob = ecdh.performDH(handshakeBobKeyPair, handshakeAliceKeyPair.public)

    println("SK match? ${SK_alice.contentEquals(SK_bob)}")

    // Initialize ratchet states
    val aliceState = doubleRatchet.ratchetInitAlice(SK_alice, bobKeyPair.public)
    val bobState = doubleRatchet.ratchetInitBob(SK_bob, bobKeyPair)

    println("\n=== INIT DONE ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")

    // ---------------------------
    // Alice sends first message
    // ---------------------------
    val (header1, ct1) = crypto.ratchetEncrypt(aliceState, "Hello Bob (msg1)", AD)

    println("\n=== ALICE -> BOB msg1 ===")
    println("Header1 PN=${header1.contentToString()}")
    println("Ciphertext1 = ${CryptoUtils.b64(ct1)}")

    val pt1 = crypto.ratchetDecrypt(bobState, header1, ct1, AD)
    println("Bob decrypted msg1: ${pt1}")

    // ---------------------------
    // Alice sends second message
    // ---------------------------
    val (header2, ct2) = crypto.ratchetEncrypt(aliceState, "Hello Bob (msg2)", AD)

    println("\n=== ALICE -> BOB msg2 ===")
    println("Header2 PN=${header2.contentToString()}")
    println("Ciphertext2 = ${CryptoUtils.b64(ct2)}")

    val pt2 = crypto.ratchetDecrypt(bobState, header2, ct2, AD)
    println("Bob decrypted msg2: ${pt2}")

    // ---------------------------
    // Bob replies (this triggers DH ratchet on Bob side)
    // ---------------------------
    val (header3, ct3) = crypto.ratchetEncrypt(bobState, "Hi Alice (reply1)", AD)

    println("\n=== BOB -> ALICE reply1 ===")
    println("Header3 PN=${header3.contentToString()}")
    println("Ciphertext3 = ${CryptoUtils.b64(ct3)}")

    val pt3 = crypto.ratchetDecrypt(aliceState, header3, ct3, AD)
    println("Alice decrypted reply1: ${pt3}")

    // ---------------------------
    // Out-of-order test:
    // Alice sends 2 messages, Bob receives second first
    // ---------------------------
    val (header4, ct4) = crypto.ratchetEncrypt(aliceState, "Out-of-order msgA", AD)
    val (header5, ct5) = crypto.ratchetEncrypt(aliceState, "Out-of-order msgB", AD)

    println("\n=== OUT OF ORDER TEST ===")
    println("Sending msgA (N=${header4.contentToString()})")

    // Deliver msgB first
    val pt5 = crypto.ratchetDecrypt(bobState, header5, ct5, AD)
    println("Bob decrypted msgB first: ${pt5}")

    // Deliver msgA later
    val pt4 = crypto.ratchetDecrypt(bobState, header4, ct4, AD)
    println("Bob decrypted msgA later: ${pt4}")

    println("\n=== MAX_SKIP TEST ===")

    try {
        // force Bob to skip beyond MAX_SKIP
        val many = mutableListOf<Pair<ByteArray, ByteArray>>()

        for (i in 0..20) {
            many.add(crypto.ratchetEncrypt(aliceState, "skip-test-$i", AD))
        }

        // deliver only the last message, skipping a lot
        val (hLast, cLast) = many.last()
        val ptLast = crypto.ratchetDecrypt(bobState, hLast, cLast, AD)

        println("Bob decrypted last skipped message: ${ptLast}")
    } catch (e: Exception) {
        println("MAX_SKIP triggered correctly: ${e.message}")
    }

    println("\n=== FINAL STATES ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")
}

 */

fun main() {
    val ecdh = EllipticCurveDiffieHellman()
    val kdf = KDFChain()
    val doubleRatchet = DoubleRatchet(kdf, ecdh)
    val crypto = EncryptionAndDecryption()

    val AD = "associated-data".toByteArray()

    // Bob has a long-term ratchet keypair (initial public key Alice knows)
    val bobKeyPair = ecdh.generateEllipticCurveKeyPair()

    // SK must be a shared secret from some handshake (simulate using ECDH here)
    val handshakeAliceKeyPair = ecdh.generateEllipticCurveKeyPair()
    val handshakeBobKeyPair = ecdh.generateEllipticCurveKeyPair()
    val SK_alice = ecdh.performDH(handshakeAliceKeyPair, handshakeBobKeyPair.public)
    val SK_bob = ecdh.performDH(handshakeBobKeyPair, handshakeAliceKeyPair.public)

    println("SK match? ${SK_alice.contentEquals(SK_bob)}")

    // Initialize ratchet states
    val (rkA, ckA, hkA) = kdf.kdfRootKeyHeaderEncryption(
            SK_alice,
            ecdh.performDH(
                handshakeAliceKeyPair,
                bobKeyPair.public)
    )

    val (rkB, ckB, nhkB) = kdf.kdfRootKeyHeaderEncryption(
            SK_bob,
            ecdh.performDH(
                bobKeyPair,
                handshakeAliceKeyPair.public)
    )

    val aliceState = doubleRatchet.ratchetInitAliceHE(
        SK_alice,
        bobKeyPair.public,
        hkA,
        nhkB // or NHK depending on your design
    )

    val bobState = doubleRatchet.ratchetInitBobHE(
        SK_bob,
        bobKeyPair,
        hkA,
        nhkB
    )



    println("\n=== INIT DONE ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")

    // ---------------------------
    // Alice sends first message
    // ---------------------------
    val (header1, ct1) = crypto.ratchetEncryptHE(aliceState, "Hello Bob (msg1)", AD)

    println("\n=== ALICE -> BOB msg1 ===")
    println("Header1 PN=${header1.contentToString()}")
    println("Ciphertext1 = ${CryptoUtils.b64(ct1)}")

    val pt1 = crypto.ratchetDecryptHE(bobState, header1, ct1, AD)
    println("Bob decrypted msg1: ${pt1}")

    // ---------------------------
    // Alice sends second message
    // ---------------------------
    val (header2, ct2) = crypto.ratchetEncryptHE(aliceState, "Hello Bob (msg2)", AD)

    println("\n=== ALICE -> BOB msg2 ===")
    println("Header2 PN=${header2.contentToString()}")
    println("Ciphertext2 = ${CryptoUtils.b64(ct2)}")

    val pt2 = crypto.ratchetDecryptHE(bobState, header2, ct2, AD)
    println("Bob decrypted msg2: ${pt2}")

    // ---------------------------
    // Bob replies (this triggers DH ratchet on Bob side)
    // ---------------------------
    val (header3, ct3) = crypto.ratchetEncryptHE(bobState, "Hi Alice (reply1)", AD)

    println("\n=== BOB -> ALICE reply1 ===")
    println("Header3 PN=${header3.contentToString()}")
    println("Ciphertext3 = ${CryptoUtils.b64(ct3)}")

    val pt3 = crypto.ratchetDecryptHE(aliceState, header3, ct3, AD)
    println("Alice decrypted reply1: ${pt3}")

    // ---------------------------
    // Out-of-order test:
    // Alice sends 2 messages, Bob receives second first
    // ---------------------------
    val (header4, ct4) = crypto.ratchetEncryptHE(aliceState, "Out-of-order msgA", AD)
    val (header5, ct5) = crypto.ratchetEncryptHE(aliceState, "Out-of-order msgB", AD)

    println("\n=== OUT OF ORDER TEST ===")
    println("Sending msgA (N=${header4.contentToString()})")

    // Deliver msgB first
    val pt5 = crypto.ratchetDecryptHE(bobState, header5, ct5, AD)
    println("Bob decrypted msgB first: ${pt5}")

    // Deliver msgA later
    val pt4 = crypto.ratchetDecryptHE(bobState, header4, ct4, AD)
    println("Bob decrypted msgA later: ${pt4}")

    println("\n=== MAX_SKIP TEST ===")

    try {
        // force Bob to skip beyond MAX_SKIP
        val many = mutableListOf<Pair<ByteArray, ByteArray>>()

        for (i in 0..20) {
            many.add(crypto.ratchetEncryptHE(aliceState, "skip-test-$i", AD))
        }

        // deliver only the last message, skipping a lot
        val (hLast, cLast) = many.last()
        val ptLast = crypto.ratchetDecryptHE(bobState, hLast, cLast, AD)

        println("Bob decrypted last skipped message: ${ptLast}")
    } catch (e: Exception) {
        println("MAX_SKIP triggered correctly: ${e.message}")
    }

    println("\n=== FINAL STATES ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")
}