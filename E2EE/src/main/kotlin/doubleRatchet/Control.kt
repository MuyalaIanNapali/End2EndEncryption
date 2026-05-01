package doubleRatchet

import encryptDecrypt.Decryption
import encryptDecrypt.EllipticCurveDiffieHellman
import encryptDecrypt.Encryption
import encryptDecrypt.EncryptionAndDecryptionUtility
import encryptDecrypt.HeaderDecryption
import encryptDecrypt.HeaderEncryption
import kdf.KDFChain
import org.example.Message
import org.example.PreKeyMessage
import org.example.RatchetMessage
import x3dh.PreKeyBundle
import x3dh.SignatureHelper
import x3dh.X3DHKeyManager
import x3dh.X3dh

class Control {
    private val util = EncryptionAndDecryptionUtility()
    private val ecdh = EllipticCurveDiffieHellman()
    private val kdf = KDFChain()
    private val doubleRatchet = DoubleRatchet(kdf, ecdh)
    private val decryptPreKeyCipherText = Decryption()
    private val encryptPreKeyPlainText = Encryption()
    private val decHE = HeaderDecryption()
    private val encHE = HeaderEncryption()

    private val sig = SignatureHelper()

    fun decryption(
        message: Message,
        AD : ByteArray,
        state : RatchetStateHE ?= null,
        receiverKeyManager : X3DHKeyManager? = null
    ):Pair<RatchetStateHE,String>{
        when(message){
            is PreKeyMessage -> {
                println("Decryption of PreKeyMessage")
                // Call the decryption function for PreKeyMessage
                val receiverX3dh = X3dh(
                    ecdh,
                    sig,
                    requireNotNull(receiverKeyManager)
                )

                val SK_bob = receiverX3dh.initReceiverX3DH(
                    receiverKeyManager,
                    util.decodePublicKey(message.IKs),
                    util.decodePublicKey(message.EKs),
                    message.opkId
                )

                val (hkr, nhks) = kdf.initHeaderKeyKDF(

                    SK_bob,
                    ecdh.performDH(
                        receiverKeyManager.signedPreKeyPair.private,
                        util.decodePublicKey(message.EKs))
                )

                var receiverState = doubleRatchet.ratchetInitReceiverHE(
                    SK_bob,
                    receiverKeyManager.signedPreKeyPair,
                    hkr,
                    nhks
                )
                val dhRatchetState = EncryptionAndDecryptionUtility().DHRatchetPreKeyMessage(
                    receiverState,
                    message.DHs)

                receiverState = dhRatchetState

                val (receiverNewState,pt1) = decryptPreKeyCipherText.decryptPreKeyMessage(
                    receiverState,
                    message.ciphertext,
                    AD)

                return Pair(receiverNewState,pt1)
            }
            is RatchetMessage -> {
                println("Decryption of RatchetMessage")
                val (bobNewState2,pt2) = decHE.ratchetDecryptHE(
                    requireNotNull(state),
                    message.encryptedHeader,
                    message.ciphertext,
                    AD)

                return Pair(bobNewState2,pt2)
            }
             else -> throw IllegalArgumentException("Unknown message type")

        }
    }

    fun encryption(
        AD : ByteArray,
        plainText: String,
        state: RatchetStateHE?=null,
        receiverPreKeyBundle: PreKeyBundle?=null,
        senderPreKeyBundle: PreKeyBundle?=null,
        senderKeyManager : X3DHKeyManager?=null,
    ): Pair<RatchetStateHE, Message>{
        if (state == null){

            val senderX3dh = X3dh(
                ecdh,
                sig,
                requireNotNull(senderKeyManager)
            )

            val (SKsender,EKPair,opkId) = senderX3dh.initSenderX3DH(
                senderKeyManager,
                requireNotNull(receiverPreKeyBundle)
            )


            val senderIK=senderPreKeyBundle!!.IKpub


            val (hks, nhkr) = kdf.initHeaderKeyKDF(
                SKsender,
                ecdh.performDH(
                    EKPair.private,
                    util.decodePublicKey(receiverPreKeyBundle.SPKpub))
            )



            var senderState= doubleRatchet.ratchetInitSenderHE(
                SKsender,
                util.decodePublicKey(receiverPreKeyBundle.SPKpub),
                hks,
                nhkr
            )

            val (newState1,ct1) = encryptPreKeyPlainText.encryptPreKeyMessage(
                senderState,
                plainText,
                AD)

            return Pair(
                newState1,
                PreKeyMessage(
                    IKs = senderIK,
                    EKs = EKPair.public.encoded,
                    DHs = newState1.DHs.public.encoded,
                    opkId = opkId,
                    ciphertext = ct1
                )
            )
        }else{
            val (newState,encryptedHeader, cipherText) = encHE.ratchetEncryptHE(
                state,
                plainText,
                AD)

            return Pair(
                newState,
                RatchetMessage(
                    encryptedHeader = encryptedHeader,
                    ciphertext = cipherText
                )
            )
        }

    }
}