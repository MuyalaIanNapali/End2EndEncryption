package org.e2ee.data.remote.users

import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.network.safeApiCall
import org.e2ee.data.remote.users.dto.RefreshRequest
import org.e2ee.data.remote.users.dto.RefreshResponse
import javax.inject.Inject

class RemoteAuthRepository @Inject constructor(
    private val authApi: AuthApi
){
        suspend fun refreshToken(request: RefreshRequest): ApiResult<RefreshResponse> {
            return safeApiCall {
                authApi.refreshToken(request)
            }
        }
}