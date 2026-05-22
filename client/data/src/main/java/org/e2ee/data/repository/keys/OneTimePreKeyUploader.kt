package org.e2ee.data.repository.keys

import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.RemoteKeyManagerRepository
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.network.ApiResult
import javax.inject.Inject

class OneTimePreKeyUploader @Inject constructor(
    private val remoteKeyManagerRepository: RemoteKeyManagerRepository,
    private val keysRepository: UserKeysRepository,
    private val opkRepository: OneTimePreKeysRepository
) {

    suspend fun updateOneTimePreKeys(): ApiResult<Unit> {
        return try {
            val userKeys = keysRepository.getUserKeys()
                ?: return ApiResult.UnknownError("User keys not found")

            val userId = userKeys.userId
                ?: return ApiResult.UnknownError("User server ID not found. User may not be registered.")

            var oneTimePreKeys = opkRepository.getNotUploaded()

            if (oneTimePreKeys.isNullOrEmpty()) {
                val missingCount = 100 - opkRepository.countNotConsumed()

                if (missingCount <= 0) {
                    return ApiResult.UnknownError(
                        "No uploadable OPKs available and OPK pool is already full"
                    )
                }

                opkRepository.generateAndStoreOPK(missingCount)
                oneTimePreKeys = opkRepository.getNotUploaded()
            }

            if (oneTimePreKeys.isNullOrEmpty()) {
                return ApiResult.UnknownError("Failed to generate uploadable OPKs")
            }

            val response = remoteKeyManagerRepository.updateOneTimePreKeys(
                UpdateOpkKeys(
                    userId = userId,
                    opkMap = oneTimePreKeys.associate { it.opkId to it.publicKey }
                )
            )

            when (response) {
                is ApiResult.Success -> {
                    opkRepository.markAsUploaded(oneTimePreKeys.map { it.opkId })
                    response
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to update one-time pre-keys")
        }
    }
}