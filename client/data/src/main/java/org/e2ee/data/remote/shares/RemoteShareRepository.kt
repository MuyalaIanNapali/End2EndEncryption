package org.e2ee.data.remote.shares

import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.network.safeApiCall
import org.e2ee.data.remote.shares.dto.ShareResponse
import org.e2ee.data.remote.shares.dto.UpdateSharesRequest
import javax.inject.Inject

class RemoteShareRepository @Inject constructor(
    private val remoteSharesApi: RemoteSharesApi
) {
    suspend fun getUserShare() : ApiResult<ShareResponse> {
        return safeApiCall {
            remoteSharesApi.getUserShare()
        }
    }

    suspend fun updateUserShare(request: UpdateSharesRequest) : ApiResult<Unit> {
        return safeApiCall {
            remoteSharesApi.updateUserShare(request)
        }
    }
}