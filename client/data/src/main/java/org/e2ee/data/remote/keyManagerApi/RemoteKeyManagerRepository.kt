package org.e2ee.data.remote.keyManagerApi

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.network.safeApiCall
import javax.inject.Inject

class RemoteKeyManagerRepository @Inject constructor(
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

    suspend fun updatePreKeyBundle(request: PreKeyBundleDto): ApiResult<Unit> {
        return safeApiCall { api.updatePreKeyBundle(request) }
    }

}