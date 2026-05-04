package encryptDecrypt

import doubleRatchet.RatchetStateHE
import doubleRatchet.deepCopy
import kdf.KDFChain
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.PublicKey

data class HEADER(
    var dhPublic: PublicKey,
    var PN: Int,
    var N: Int
)

class Encryption {
    private val sha256 = MessageDigest.getInstance("SHA-256")
    private val util = EncryptionAndDecryptionUtility()


    fun hashPlaintextNonce(mk: ByteArray): ByteArray {
        val domain = "PLAINTEXT_NONCE_DERIVATION".toByteArray()
        return sha256.digest(domain+mk)
    }

    fun plainTextEncryption(
        messageKey: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray
    ): ByteArray {

        val aesKeyEncrypt = SecretKeySpec(messageKey, "AES")
        val nonceFull = hashPlaintextNonce(messageKey)

        val nonce = nonceFull.copyOfRange(0,12)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyEncrypt, spec)
        cipher.updateAAD(associatedData)

        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }

    fun ratchetSendKey(state: RatchetStateHE): Pair<RatchetStateHE, ByteArray>{
        var ratchetState = state.deepCopy()
        val (newChainKey,messageKey)= KDFChain().kdfChainKey(requireNotNull(ratchetState.CKs))

        return Pair(state.copy(
            CKs = newChainKey,
            Ns = ratchetState.Ns + 1
        ),messageKey)


    }
    fun encryptPreKeyMessage(
        state: RatchetStateHE,
        plainText : String,
        AD : ByteArray
    ): Pair<RatchetStateHE, ByteArray> {
        var newState = state.deepCopy()

        val(state1,messageKey) = ratchetSendKey(newState)
        newState = state1

         //val header = HEADER(state.DHs.public, state.PN, state.Ns)

        //val header = HEADER(state.DHs.public, state.PN,Ns,)

        //val headerBytes = util.encodeHeader(header)

        return Pair(
            newState,
            plainTextEncryption(
                messageKey,
                plainText.toByteArray(),
                AD
            )
        )
    }

}