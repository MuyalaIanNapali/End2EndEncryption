package org.e2ee.data.repository.keys

import android.util.Log
import kotlinx.datetime.LocalDateTime
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.RemoteKeyManagerRepository
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto
import org.e2ee.data.remote.network.ApiResult
import javax.inject.Inject

class PreKeyBundleUploader @Inject constructor(
    private val remoteKeyManagerRepository: RemoteKeyManagerRepository,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository
) {

    suspend fun updatePreKeyBundle(): ApiResult<Unit> {
        return try {
            val userKeys = keysRepository.getUserKeys()
                ?: return ApiResult.UnknownError("User keys not found")

            val userId = userKeys.userId
                ?: return ApiResult.UnknownError("User server ID not found. User may not be registered.")

            val signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
                ?: return ApiResult.UnknownError("Active signed pre-key not found")

            val oneTimePreKeys = opkRepository.getNotUploaded()

            if (oneTimePreKeys.isNullOrEmpty()) {
                return ApiResult.UnknownError("No uploadable one-time pre-keys available")
            }

            val request = PreKeyBundleDto(
                userId = userId,
                identityKey = userKeys.identityKeyPublic,
                identityKeySigning = userKeys.identitySigningKeyPublic,
                signedPreKeyBundle = signedPreKey,
                opkMap = oneTimePreKeys.associate { it.opkId to it.publicKey }
            )

            when (val response = remoteKeyManagerRepository.updatePreKeyBundle(request)) {
                is ApiResult.Success -> {
                    opkRepository.markAsUploaded(oneTimePreKeys.map { it.opkId })
                    response
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to update pre-key bundle")
        }
    }
}