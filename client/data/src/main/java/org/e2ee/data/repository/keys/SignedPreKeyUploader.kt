package org.e2ee.data.repository.keys

import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.RemoteKeyManagerRepository
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import javax.inject.Inject

class SignedPreKeyUploader @Inject constructor(
    private val remoteKeyManagerRepository: RemoteKeyManagerRepository,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository
) {

    suspend fun updateSignedPreKey(): ApiResult<Unit> {
        return try {
            val userKeys = keysRepository.getUserKeys()
                ?: return ApiResult.UnknownError("User keys not found")

            val userId = userKeys.userId
                ?: return ApiResult.UnknownError("User server ID not found. User may not be registered.")

            spkRepository.rotateIfExpired()

            val signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
                ?: return ApiResult.UnknownError("Active signed pre-key not found")

            remoteKeyManagerRepository.updateSignedPreKey(
                UpdateSignedPreKeyBundle(
                    userId = userId,
                    keyId = signedPreKey.keyId,
                    signedPreKey = signedPreKey.signedPreKey,
                    signature = signedPreKey.signature
                )
            )
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to update signed pre-key")
        }
    }
}