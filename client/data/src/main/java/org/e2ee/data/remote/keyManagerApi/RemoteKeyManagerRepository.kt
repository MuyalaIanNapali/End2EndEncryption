package org.e2ee.data.remote.keyManagerApi

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundle
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.network.safeApiCall

class RemoteKeyManagerRepository(
    private val api: KeyManagerApi
) {
    suspend fun updateSignedPreKey(request: UpdateSignedPreKeyBundle): ApiResult<Unit> {
        return safeApiCall { api.updateSignedPreKey(request) }
    }

    suspend fun updateOneTimePreKeys(request: UpdateOpkKeys): ApiResult<Unit> {
        return safeApiCall {
            api.updateOneTimePreKeys(request)
        }
    }

    suspend fun updatePreKeyBundle(request: PreKeyBundle): ApiResult<Unit> {
        return safeApiCall { api.updatePreKeyBundle(request) }
    }

}