package server.keymanager

import jakarta.transaction.Transactional
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import server.exceptionHandler.UserNotFoundException
import server.exceptionHandler.UserPublicKeyNotFoundException
import server.keymanager.dto.PreKeyBundle
import server.keymanager.dto.PreKeyBundleResponse
import server.keymanager.dto.PreKeyVerification
import server.keymanager.dto.SignedPreKeyBundle
import server.keymanager.dto.UpdateOpkKeys
import server.keymanager.dto.UpdateSignedPreKeyBundle
import server.keymanager.opk.OneTimePreKeys
import server.keymanager.opk.OneTimePreKeysRepository
import java.time.LocalDateTime

@Service
class KeyManagerService(
    private val userPublicKeysRepository: UserPublicKeysRepository,
    private val oneTimePreKeysRepository: OneTimePreKeysRepository,
    private val opkNotificationRepository: OpkNotificationRepository
) {

    fun getRemainingOpkCount(userId: Long): Long {
        return oneTimePreKeysRepository.countByUserIdAndUsedFalse(userId)
    }

    private fun shouldSendOpkNotification(userId: Long, remaining: Long): Boolean {
        if (remaining >= 20) return false

        val state = opkNotificationRepository.findById(userId)
            .orElse(null)

        return state?.notificationSent != true
    }

    fun consumeOpk(userId: Long): OneTimePreKeys? {

        val opk = oneTimePreKeysRepository.getNextAvailableOPK(userId)
            ?: return null

        opk.used = true

        return oneTimePreKeysRepository.saveAndFlush(opk)
    }

    fun savePreKeyBundle(preKeyBundle: PreKeyBundle) {
        val userPublicKeys = UserPublicKeys(
            userId = preKeyBundle.userId!!,
            signedPreKeyId = preKeyBundle.signedPreKeyBundle.keyId,
            signedPreKey = preKeyBundle.signedPreKeyBundle.signedPreKey,
            signature = preKeyBundle.signedPreKeyBundle.signature,
            identityKey = preKeyBundle.identityKey,
            identityKeySigning = preKeyBundle.identityKeySigning
        )
        userPublicKeysRepository.save(userPublicKeys)

        preKeyBundle.opkMap.forEach { (keyId, keyValue) ->
            val oneTimePreKey = OneTimePreKeys(
                userId = preKeyBundle.userId!!,
                keyId = keyId,
                key = keyValue
            )
            oneTimePreKeysRepository.save(oneTimePreKey)
        }
    }

    @Transactional
    fun getPreKeyBundle(userId: Long): PreKeyBundleResponse? {
        val userPublicKeys = userPublicKeysRepository.findByUserId(userId)
            ?: return null


        val oneTimePreKey = consumeOpk(userId)

        val remaining = getRemainingOpkCount(userId)

        if(shouldSendOpkNotification(userId,remaining)){
            val state = opkNotificationRepository.findById(userId).orElse(
                OpkNotificationState(userId)
            )

            //TODO : send notification
            opkNotificationRepository.save(
                OpkNotificationState(
                    userId = userId,
                    notificationSent = true,
                    lastNotifiedAt = LocalDateTime.now()
                )
            )
        }

        return PreKeyBundleResponse(
            identityKey = userPublicKeys.identityKey,
            signedPreKeyBundle = SignedPreKeyBundle(
                keyId = userPublicKeys.signedPreKeyId,
                signedPreKey = userPublicKeys.signedPreKey,
                signature = userPublicKeys.signature
            ),
            identityKeySigning = userPublicKeys.identityKeySigning,
            opkPair = oneTimePreKey?.let { it.keyId to it.key } // null if none
        )
    }

    fun updateSignedPreKeyBundle(updateSignedPreKeyBundle: UpdateSignedPreKeyBundle){
        val userPublicKeys = userPublicKeysRepository.findByUserId(updateSignedPreKeyBundle.userId)
            ?: throw UserNotFoundException()

        userPublicKeys.updateFromSPK(updateSignedPreKeyBundle)
        userPublicKeysRepository.save(userPublicKeys)
    }

    fun updatePreKeyBundle(preKeyBundle: PreKeyBundle){
        val userPublicKeys = userPublicKeysRepository.findByUserId(preKeyBundle.userId!!)
            ?: throw UserPublicKeyNotFoundException()

        userPublicKeys.updateFromPreKeyBundle(preKeyBundle)

        userPublicKeysRepository.save(userPublicKeys)
        preKeyBundle.opkMap.forEach { (keyId, keyValue) ->
            val oneTimePreKey = OneTimePreKeys(
                userId = preKeyBundle.userId!!,
                keyId = keyId,
                key = keyValue
            )
            oneTimePreKeysRepository.save(oneTimePreKey)
        }
    }

    fun getPreKeyVerificationBundle(userId: Long): PreKeyVerification? {
        val preKeys =userPublicKeysRepository.findByUserId(userId)
            ?: return null

        return preKeys.toPreKeyVerification()
    }

}