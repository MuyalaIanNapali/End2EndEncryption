package org.e2ee.crypto



import org.e2ee.crypto.doubleRatchet.Control
import org.e2ee.crypto.doubleRatchet.DoubleRatchet
import org.e2ee.crypto.encryptDecrypt.Decryption
import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import org.e2ee.crypto.encryptDecrypt.Encryption
import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import org.e2ee.crypto.encryptDecrypt.HeaderDecryption
import org.e2ee.crypto.encryptDecrypt.HeaderEncryption
import org.e2ee.crypto.kdf.KDFChain
import org.e2ee.crypto.x3dh.PreKeyBundle
import org.e2ee.crypto.x3dh.SignatureHelper
import org.e2ee.crypto.x3dh.X3DHKeyManager
import org.e2ee.crypto.x3dh.X3dh
import java.util.*

object CryptoUtils {
    fun b64(data: ByteArray): String =
        Base64.getEncoder().encodeToString(data)
}




fun main() {
    val ecdh = EllipticCurveDiffieHellman()
    val kdf = KDFChain()
    val message = Message()
    val e2eeControl = Control()
    val doubleRatchet = DoubleRatchet(kdf, ecdh)
    val util = EncryptionAndDecryptionUtility()
    val enc = Encryption()
    val dec = Decryption()
    val enc_HE = HeaderEncryption()
    val dec_HE = HeaderDecryption()

    val (aliceKeyManager,alicePreKeyBundle) = createAccount()
    val (bobKeyManager,bobPreKeyBundle) = createAccount()

    val AD = "associated-data".toByteArray()
    println("\n=== INIT ALICE DONE ===")

    // ---------------------------
    // Alice sends first message
    // --------------------------
    //no header encryption
    val (newState1,message1) = e2eeControl.encryption(
        AD,
        "Hello Bob(msg1)",
        null,
        bobPreKeyBundle,
        alicePreKeyBundle,
        aliceKeyManager,
    )

    var aliceState = newState1

    println("\n=== ALICE -> BOB msg1 ===")
    println("Ciphertext1 = ${message1}")

    val (bobNewState,pt1) = e2eeControl.decryption(
        message1,
        AD,
        null,
        bobKeyManager)

    var bobState = bobNewState

    println("Bob decrypted msg1: ${pt1}")

    // ---------------------------
    // Alice sends second message
    // ---------------------------
    val (newState2,message2) = e2eeControl.encryption(
        AD,
        "Hello Bob(msg2)",
        aliceState)

    aliceState = newState2

    println("\n=== ALICE -> BOB msg2 ===")
    println("Ciphertext2 = ${CryptoUtils.b64(message2.toString().toByteArray())}")

    val (bobNewState2,pt2) = e2eeControl.decryption(
        message2,
        AD,
        bobState)

    bobState = bobNewState2

    println("Bob decrypted msg2: ${pt2}")

    // ---------------------------
    // Bob replies (this triggers DH ratchet on Bob side)
    // ---------------------------
    val (bobState3,message3) = e2eeControl.encryption(
        AD,
        "Hello Bob(msg3)",
        bobState)

    bobState = bobState3

    println("\n=== BOB -> ALICE reply1 ===")

    val (aliceState3,pt3) = e2eeControl.decryption(
        message3,
        AD,
        aliceState)

    aliceState = aliceState3

    println("Alice decrypted reply1: ${pt3}")

    // ---------------------------
    // Out-of-order test:
    // Alice sends 2 messages, Bob receives second first
    // ---------------------------
    val (aliceState4,message4) = e2eeControl.encryption(
        AD,
        "Out-of-order msgA",
        aliceState)

    aliceState = aliceState4

    val (aliceState5,message5) = e2eeControl.encryption(
        AD,
        "Out-of-order msgB",
        aliceState)

    aliceState = aliceState5

    println("\n=== OUT OF ORDER TEST ===")

    // Deliver msgB first
    val (bobState4,pt5) = e2eeControl.decryption(
        message5,
        AD,
        bobState)

    bobState = bobState4

    println("Bob decrypted msgB first: ${pt5}")

    // Deliver msgA later
    val (bobState5,pt4) = e2eeControl.decryption(
        message4,
        AD,
        bobState)

    bobState = bobState5

    println("Bob decrypted msgA later: ${pt4}")

    println("\n=== MAX_SKIP TEST ===")

    try {
        // force Bob to skip beyond MAX_SKIP
        val many = mutableListOf<Message>() // only store messages

        for (i in 0..20) {
            val (newState,message) =
                e2eeControl.encryption(AD, "skip-test-$i", aliceState)

            aliceState = newState
            many.add(message)
        }

        // deliver only the last message, skipping a lot
        val message = many.last()
        val (bobState6,ptLast) = e2eeControl.decryption(
            message,
            AD,
            bobState)

        bobState = bobState6

        println("Bob decrypted last skipped message: ${ptLast}")
    } catch (e: Exception) {
        println("MAX_SKIP triggered correctly: ${e.message}")
    }

    println("\n=== FINAL STATES ===")
    println("Alice: $aliceState")
    println("Bob:   $bobState")


}