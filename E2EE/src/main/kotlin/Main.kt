package org.example


import doubleRatchet.DoubleRatchet
import encryptDecrypt.Decryption
import encryptDecrypt.EllipticCurveDiffieHellman
import encryptDecrypt.Encryption
import encryptDecrypt.HeaderDecryption
import encryptDecrypt.HeaderEncryption
import kdf.KDFChain
import java.util.*

object CryptoUtils {
    fun b64(data: ByteArray): String =
        Base64.getEncoder().encodeToString(data)
}

fun main() {
    val ecdh = EllipticCurveDiffieHellman()
    val kdf = KDFChain()
    val doubleRatchet = DoubleRatchet(kdf, ecdh)
    val enc = Encryption()
    val dec = Decryption()
    val enc_HE = HeaderEncryption()
    val dec_HE = HeaderDecryption()

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
    val (rkA, ckA, hkA) = kdf.kdfRootKey(
        SK_alice,
        ecdh.performDH(
            handshakeAliceKeyPair,
            bobKeyPair.public)
    )

    val (rkB, ckB, nhkB) = kdf.kdfRootKey(
        SK_bob,
        ecdh.performDH(
            bobKeyPair,
            handshakeAliceKeyPair.public)
    )

    var aliceState= doubleRatchet.ratchetInitAliceHE(
        SK_alice,
        bobKeyPair.public,
        hkA,
        nhkB // or NHK depending on your design
    )

    var bobState = doubleRatchet.ratchetInitBobHE(
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
    val (newState1,header1, ct1) = enc_HE.ratchetEncryptHE(
        aliceState,
        "Hello Bob (msg1)",
        AD)

    aliceState = newState1

    println("\n=== ALICE -> BOB msg1 ===")
    println("Header1 PN=${header1.contentToString()}")
    println("Ciphertext1 = ${CryptoUtils.b64(ct1)}")

    val (bobNewState,pt1) = dec_HE.ratchetDecryptHE(
        bobState,
        header1,
        ct1,
        AD)

    bobState = bobNewState

    println("Bob decrypted msg1: ${pt1}")

    // ---------------------------
    // Alice sends second message
    // ---------------------------
    val (newState2,header2, ct2) = enc_HE.ratchetEncryptHE(
        aliceState,
        "Hello Bob (msg2)",
        AD)

    aliceState = newState2

    println("\n=== ALICE -> BOB msg2 ===")
    println("Header2 PN=${header2.contentToString()}")
    println("Ciphertext2 = ${CryptoUtils.b64(ct2)}")

    val (bobNewState2,pt2) = dec_HE.ratchetDecryptHE(
        bobState,
        header2,
        ct2,
        AD)

    bobState = bobNewState2

    println("Bob decrypted msg2: ${pt2}")

    // ---------------------------
    // Bob replies (this triggers DH ratchet on Bob side)
    // ---------------------------
    val (bobState3,header3, ct3) = enc_HE.ratchetEncryptHE(
        bobState,
        "Hi Alice (reply1)",
        AD)

    bobState = bobState3

    println("\n=== BOB -> ALICE reply1 ===")
    println("Header3 PN=${header3.contentToString()}")
    println("Ciphertext3 = ${CryptoUtils.b64(ct3)}")

    val (aliceState3,pt3) = dec_HE.ratchetDecryptHE(
        aliceState,
        header3,
        ct3,
        AD)

    aliceState = aliceState3

    println("Alice decrypted reply1: ${pt3}")

    // ---------------------------
    // Out-of-order test:
    // Alice sends 2 messages, Bob receives second first
    // ---------------------------
    val (aliceState4,header4, ct4) = enc_HE.ratchetEncryptHE(
        aliceState,
        "Out-of-order msgA",
        AD)

    aliceState = aliceState4

    val (aliceState5,header5, ct5) = enc_HE.ratchetEncryptHE(
        aliceState,
        "Out-of-order msgB",
        AD)

    aliceState = aliceState5

    println("\n=== OUT OF ORDER TEST ===")
    println("Sending msgA (N=${header4.contentToString()})")

    // Deliver msgB first
    val (bobState4,pt5) = dec_HE.ratchetDecryptHE(
        bobState,
        header5,
        ct5,
        AD)

    bobState = bobState4

    println("Bob decrypted msgB first: ${pt5}")

    // Deliver msgA later
    val (bobState5,pt4) = dec_HE.ratchetDecryptHE(
        bobState,
        header4,
        ct4,
        AD)

    bobState = bobState5

    println("Bob decrypted msgA later: ${pt4}")

    println("\n=== MAX_SKIP TEST ===")

    try {
        // force Bob to skip beyond MAX_SKIP
        val many = mutableListOf<Pair<ByteArray, ByteArray>>() // only store messages

        for (i in 0..20) {
            val (newState, header, ct) =
                enc_HE.ratchetEncryptHE(aliceState, "skip-test-$i", AD)

            aliceState = newState
            many.add(header to ct)
        }

        // deliver only the last message, skipping a lot
        val (hLast, cLast) = many.last()
        val (bobState6,ptLast) = dec_HE.ratchetDecryptHE(
            bobState,
            hLast,
            cLast,
            AD)

        bobState = bobState6

        println("Bob decrypted last skipped message: ${ptLast}")
    } catch (e: Exception) {
        println("MAX_SKIP triggered correctly: ${e.message}")
    }

    println("\n=== FINAL STATES ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")
}