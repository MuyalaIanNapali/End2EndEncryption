package org.e2ee.data.local.signedPreKeys

import androidx.annotation.WorkerThread
import org.e2ee.crypto.Crypto
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.dto.SignedPreKeyBundle
import java.util.UUID
import javax.inject.Inject

class SignedPreKeysRepository @Inject constructor(
    private val dao: SignedPreKeysDao,
    private val userKeysRepository: UserKeysRepository,
    private val crypto: Crypto
) {

    @WorkerThread
    suspend fun rotateIfExpired() {
        val now = System.currentTimeMillis()

        // First delete old inactive keys whose 48-hour grace period is finished
        dao.deleteExpiredInactiveSignedPreKeys(now)

        val activeSignedPreKey = dao.getActiveSignedPreKey()

        if (activeSignedPreKey == null) {
            createNewActiveSignedPreKey()
            return
        }

        val hasExpired = activeSignedPreKey.expiresAt <= now

        if (!hasExpired) return

        val deleteAfter = now + 48L * 60 * 60 * 1000

        dao.markAsInactive(
            signedPreKeyId = activeSignedPreKey.signedPreKeyId,
            deleteAfter = deleteAfter
        )

        createNewActiveSignedPreKey()
    }

    @WorkerThread
    suspend fun getActiveSignedPreKeyBundle(): SignedPreKeyBundle? {
        return dao.getActiveSignedPreKeyBundle()
    }

    @WorkerThread
    private suspend fun createNewActiveSignedPreKey() {
        val userKeys = userKeysRepository.getUserKeys()
            ?: throw IllegalStateException("User keys not initialized")

        val signedPreKeyPairAndSignature = crypto.generateSPKAndSignature(
            userKeys.identitySigningKeyPrivate
        )

        dao.insertSignedPreKey(
            SignedPreKeys(
                signedPreKeyId = generateSignedPreKeyId(),
                localUserId = 1,
                publicKey = signedPreKeyPairAndSignature.first.first,
                privateKey = signedPreKeyPairAndSignature.first.second,
                signature = signedPreKeyPairAndSignature.second,
                active = true,
                uploaded = false
            )
        )
    }

    @WorkerThread
    suspend fun getSpkById(signedPreKeyId: String): Pair<ByteArray, ByteArray>? {
        val spk = dao.getSignedPreKeyById(signedPreKeyId)
        return spk?.let { Pair(it.publicKey, it.privateKey) }
    }

    private fun generateSignedPreKeyId(): String {
        return "SPK_${System.currentTimeMillis()}_${UUID.randomUUID()}"
    }

    @WorkerThread
    suspend fun getFullActiveSignedPreKey(): SignedPreKeys? {
        return dao.getActiveSignedPreKey()
    }


}