package x3dh

import encryptDecrypt.EllipticCurveDiffieHellman
import encryptDecrypt.EncryptionAndDecryptionUtility
import kdf.KDFChain
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

class X3dh(
    private val ecc: EllipticCurveDiffieHellman,
    private val sig: SignatureHelper,
    private val keyManager: X3DHKeyManager
) {

    private val util = EncryptionAndDecryptionUtility()

    fun publishKeys(): PreKeyBundle{

        keyManager.initIdentityKeys()
        keyManager.generateSignedPreKey()

        val identitySigningKey = keyManager.identitySigningKey

        val signature = sig.signMessage(
            keyManager.signedPreKeyPair.public.encoded,
            identitySigningKey.private
        )

        val opkMap = keyManager.generateOPK(
            10,
            keyManager.opkStore
        )

        return PreKeyBundle(
                IKpub = keyManager.identityKeyPair.public.encoded,
                SPKpub = keyManager.signedPreKeyPair.public.encoded,
                OPKpub = opkMap,
                signature = signature,
                IKsigPub = identitySigningKey.public.encoded
            )
    }

    fun initSender(
        keyManager: X3DHKeyManager,
        preKeyBundle: PreKeyBundle
    ) : Triple<ByteArray, ByteArray,String ?> {
        val IKpub = util.decodePublicKey(preKeyBundle.IKpub)
        val SPKpub = util.decodePublicKey(preKeyBundle.SPKpub)

        val validSignature = sig.verifySignature(
            preKeyBundle.SPKpub,
            preKeyBundle.signature,
            sig.decodeEdPublicKey(preKeyBundle.IKsigPub)
        )

        if (!validSignature) {
            throw IllegalArgumentException("Invalid signature on signed pre-key")
        }

        val OPKpub : Map<String, ByteArray>  = preKeyBundle.OPKpub ?: emptyMap()

        val senderEphemeralKP = ecc.generateEllipticCurveKeyPair()
        val EKs = senderEphemeralKP.public.encoded


        // Perform the X3DH key agreement
        val dh1 = ecc.performDH(keyManager.identityKeyPair.private, SPKpub)
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



            return Triple(secretKey,EKs,opkId)
        }else{

            val secretKey =KDFChain().kdfX3DH(concat(dh1, dh2, dh3),info)

            senderEphemeralKP.private.destroy()

            clear(dh1)
            clear(dh2)
            clear(dh3)

            return Triple(secretKey,EKs,null)
        }

    }

    fun initReciever(
        keyManager: X3DHKeyManager,
        IKs: PublicKey,
        EKs: PublicKey,
        opkId:String?
    ) : ByteArray {
        val dh1 = ecc.performDH(keyManager.signedPreKeyPair.private, IKs)
        val dh2 = ecc.performDH(keyManager.identityKeyPair.private, EKs)
        val dh3 = ecc.performDH(keyManager.signedPreKeyPair.private, EKs)

        val info = "X3DH".toByteArray()

        if(opkId != null){
            val opkPrivate: PrivateKey  = keyManager.opkStore.get(opkId) ?: throw IllegalArgumentException("OPK not found for id: $opkId")

            val dh4 = ecc.performDH(opkPrivate, EKs)

            keyManager.removeOPK(opkId)

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