package org.e2ee.data.repository.keys

import androidx.annotation.WorkerThread
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository

class UserPreKeyInitializer(
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository
) {

    @WorkerThread
    suspend fun initUserPreKeys(): Boolean {
        return try {
            val existingKeys = keysRepository.getUserKeys()
            if (existingKeys == null) {
                keysRepository.generateAndStoreUserKeys()
            }

            spkRepository.rotateIfExpired()

            val availableOpks = opkRepository.countNotConsumed()
            if (availableOpks <= 0) {
                opkRepository.generateAndStoreOPK(100)
            }

            true
        } catch (e: Exception) {
            println("Error initializing user keys: ${e.message}")
            false
        }
    }
}