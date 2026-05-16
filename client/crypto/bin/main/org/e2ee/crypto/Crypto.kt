package org.e2ee.crypto

import org.e2ee.crypto.doubleRatchet.DoubleRatchet
import org.e2ee.crypto.encryptDecrypt.Decryption
import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import org.e2ee.crypto.encryptDecrypt.Encryption
import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import org.e2ee.crypto.encryptDecrypt.HeaderDecryption
import org.e2ee.crypto.encryptDecrypt.HeaderEncryption
import org.e2ee.crypto.entities.DecryptMessageDto
import org.e2ee.crypto.entities.DecryptPreKeyMessageDto
import org.e2ee.crypto.kdf.KDFChain
import org.e2ee.crypto.x3dh.PreKeyBundle
import org.e2ee.crypto.x3dh.SignatureHelper
import org.e2ee.crypto.x3dh.X3DHKeyManager
import org.e2ee.crypto.x3dh.X3dh
import org.e2ee.crypto.entities.DecryptionResult
import org.e2ee.crypto.entities.EncryptMessageDto
import org.e2ee.crypto.entities.EncryptPreKeyMessageDto
import org.e2ee.crypto.entities.EncryptionResult
import java.security.KeyPair


class Crypto {
    private val util = EncryptionAndDecryptionUtility()
    private val ecdh = EllipticCurveDiffieHellman()
    private val kdf = KDFChain()
    private val doubleRatchet = DoubleRatchet(kdf, ecdh)
    private val decryptPreKeyCipherText = Decryption()
    private val encryptPreKeyPlainText = Encryption()
    private val decHE = HeaderDecryption()
    private val encHE = HeaderEncryption()
    private val sig = SignatureHelper()
    private val keyManager = X3DHKeyManager(
        ecdh,
        sig
    )

    fun decryptPreKeyMessage(
        decryptionDto: DecryptPreKeyMessageDto
    ): DecryptionResult {
        val receiverX3dh = X3dh(
            ecdh,
            sig
        )

        val sKReceiver = receiverX3dh.initReceiverX3DH(
            decryptionDto.receiverKeyManager,
            util.decodePublicKey(decryptionDto.message.IKs),
            util.decodePublicKey(decryptionDto.message.EKs),
            decryptionDto.message.opkId
        )

        val (hkr, nhks) = kdf.initHeaderKeyKDF(

            sKReceiver,
            ecdh.performDH(
                decryptionDto.receiverKeyManager.signedPreKey.private,
                util.decodePublicKey(decryptionDto.message.EKs)
            )
        )

        var receiverState = doubleRatchet.ratchetInitReceiverHE(
            sKReceiver,
            decryptionDto.receiverKeyManager.signedPreKey,
            hkr,
            nhks
        )
        val dhRatchetState = EncryptionAndDecryptionUtility().DHRatchetPreKeyMessage(
            receiverState,
            decryptionDto.message.DHs
        )

        receiverState = dhRatchetState

        val (receiverNewState, pt1) = decryptPreKeyCipherText.decryptPreKeyMessage(
            receiverState,
            decryptionDto.message.ciphertext,
            decryptionDto.associatedData
        )

        return DecryptionResult(
            plaintext = pt1,
            newState = receiverNewState
        )
    }

    fun decryptMessage(
        decryptionDto: DecryptMessageDto
    ): DecryptionResult {
        val (userNewState, pt2) = decHE.ratchetDecryptHE(
            decryptionDto.state,
            decryptionDto.message.encryptedHeader,
            decryptionDto.message.ciphertext,
            decryptionDto.associatedData
        )

        return DecryptionResult(
            plaintext = pt2,
            newState = userNewState
        )
    }

    fun encryptPreKeyMessage(
        encryptionDto: EncryptPreKeyMessageDto
    ): EncryptionResult {
        val senderX3dh = X3dh(
            ecdh,
            sig
        )

        val (sKSender, eKPair, opkId) = senderX3dh.initSenderX3DH(
            encryptionDto.senderKeyManager,
            encryptionDto.receiverPreKeyBundle
        )


        val senderIK = encryptionDto.senderPreKeyBundle.IKpub


        val (hks, nhkr) = kdf.initHeaderKeyKDF(
            sKSender,
            ecdh.performDH(
                eKPair.private,
                util.decodePublicKey(encryptionDto.receiverPreKeyBundle.SPKpub.second)
            )
        )


        val senderState = doubleRatchet.ratchetInitSenderHE(
            sKSender,
            util.decodePublicKey(encryptionDto.receiverPreKeyBundle.SPKpub.second),
            hks,
            nhkr
        )

        val (newState1, ct1) = encryptPreKeyPlainText.encryptPreKeyMessage(
            senderState,
            encryptionDto.plainText,
            encryptionDto.associatedData
        )

        return EncryptionResult(
            PreKeyMessage(
                IKs = senderIK,
                EKs = eKPair.public.encoded,
                DHs = newState1.DHs.public.encoded,
                opkId = opkId,
                ciphertext = ct1
            ),
            newState1
        )
    }


    fun encryptMessage(
        encryptionDto: EncryptMessageDto
    ): EncryptionResult {
        val (newState, encryptedHeader, cipherText) = encHE.ratchetEncryptHE(
            encryptionDto.state,
            encryptionDto.plainText,
            encryptionDto.associatedData
        )

        return EncryptionResult(
            RatchetMessage(
                encryptedHeader = encryptedHeader,
                ciphertext = cipherText
            ),
            newState,
        )
    }

    fun generateSPKAndSignature(
        signingKey: ByteArray
    ): Pair<Pair<ByteArray, ByteArray>, ByteArray> {
        return keyManager.generateSignedPreKey(
            sig.decodeEdPrivateKey(signingKey)
        )
    }

    fun generateKeyPair(): KeyPair {
        return ecdh.generateEllipticCurveKeyPair()
    }

}