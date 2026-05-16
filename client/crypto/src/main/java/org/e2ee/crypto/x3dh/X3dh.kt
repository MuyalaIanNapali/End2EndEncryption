package org.e2ee.crypto.x3dh


import org.e2ee.crypto.dto.UserKeysDecodedDto
import org.e2ee.crypto.dto.UserKeysDto
import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import org.e2ee.crypto.kdf.KDFChain
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

internal class X3dh(
    private val ecc: EllipticCurveDiffieHellman,
    private val sig: SignatureHelper
) {

    private val util = EncryptionAndDecryptionUtility()

    fun initSenderX3DH(
        userKeys: UserKeysDecodedDto,
        preKeyBundle: PreKeyBundle
    ) : Triple<ByteArray, KeyPair,String ?> {
        val IKpub = util.decodePublicKey(preKeyBundle.IKpub)
        val SPKpub = util.decodePublicKey(preKeyBundle.SPKpub.second)

        val validSignature = sig.verifySignature(
            preKeyBundle.SPKpub.second,
            preKeyBundle.signature,
            sig.decodeEdPublicKey(preKeyBundle.IKsigPub)
        )

        if (!validSignature) {
            throw IllegalArgumentException("Invalid signature on signed pre-key")
        }

        val OPKpub : Map<String, ByteArray>  = preKeyBundle.OPKpub ?: emptyMap()

        val senderEphemeralKP = ecc.generateEllipticCurveKeyPair()


        // Perform the X3DH key agreement
        val dh1 = ecc.performDH(userKeys.identityKey, SPKpub)
        val dh2 = ecc.performDH(senderEphemeralKP.private, IKpub)
        val dh3 = ecc.performDH(senderEphemeralKP.private, SPKpub)

        val info = "X3DH".toByteArray()

        if (OPKpub.isNotEmpty()) {
            val (opkId, opkPub) = OPKpub.entries.first()
            val dh4 = ecc.performDH(senderEphemeralKP.private, util.decodePublicKey(opkPub))

            //senderEphemeralKP.private.destroy()

            //delete all dh and ephemeral keys
            //keyManager.removeOPK(opkId)
            val combined = concat(dh1, dh2, dh3, dh4)

            val secretKey = KDFChain().kdfX3DH(combined,info)

            clear(dh1)
            clear(dh2)
            clear(dh3)
            clear(dh4)
            clear(combined)
            // TODO: Inform server of OPK key used



            return Triple(secretKey,senderEphemeralKP,opkId)
        }else{

            val secretKey =KDFChain().kdfX3DH(concat(dh1, dh2, dh3),info)

            senderEphemeralKP.private.destroy()

            clear(dh1)
            clear(dh2)
            clear(dh3)

            return Triple(secretKey,senderEphemeralKP,null)
        }

    }

    fun initReceiverX3DH(
        userKeys: UserKeysDecodedDto,
        IKs: PublicKey,
        EKs: PublicKey,
        opkId:String?
    ) : ByteArray {
        val dh1 = ecc.performDH(userKeys.signedPreKey.private, IKs)
        val dh2 = ecc.performDH(userKeys.identityKey, EKs)
        val dh3 = ecc.performDH(userKeys.signedPreKey.private, EKs)

        val info = "X3DH".toByteArray()

        if(opkId != null){
            val dh4 = ecc.performDH(userKeys.oneTimePreKeys, EKs)

            val combined = concat(dh1, dh2, dh3, dh4)

            val secretKey = KDFChain().kdfX3DH(combined,info)

            clear(dh1)
            clear(dh2)
            clear(dh3)
            clear(dh4)
            clear(combined)

            return secretKey

        }else{
            val combined = concat(dh1,dh2,dh3)

            val secretKey = KDFChain().kdfX3DH(combined,info)
            clear(dh1)
            clear(dh2)
            clear(dh3)
            clear(combined)
            return secretKey
        }

    }


    fun concat(vararg arrays: ByteArray): ByteArray {
        val totalSize = arrays.sumOf { it.size }
        val result = ByteArray(totalSize)

        var offset = 0
        for (arr in arrays) {
            System.arraycopy(arr, 0, result, offset, arr.size)
            offset += arr.size
        }

        return result
    }

    fun clear(bytes: ByteArray?) {
        bytes?.fill(0)
    }
}