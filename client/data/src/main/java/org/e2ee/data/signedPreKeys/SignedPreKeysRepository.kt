package org.e2ee.data.signedPreKeys

import org.e2ee.crypto.Crypto
import org.e2ee.data.userKeys.UserKeysRepository
import java.util.UUID
import javax.inject.Inject

class SignedPreKeysRepository @Inject constructor(
    private val dao: SignedPreKeysDao,
    private val userKeysRepository: UserKeysRepository,
    private val crypto: Crypto
) {

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

    private suspend fun createNewActiveSignedPreKey() {
        val userKeys = userKeysRepository.getUserKeys()
            ?: throw IllegalStateException("User keys not initialized")

        val signedPreKeyPairAndSignature = crypto.generateSPKAndSignature(
            userKeys.identitySigningKeyPriv
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

    private fun generateSignedPreKeyId(): String {
        return "SPK_${System.currentTimeMillis()}_${UUID.randomUUID()}"
    }
}