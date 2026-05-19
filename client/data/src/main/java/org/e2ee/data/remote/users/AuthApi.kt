package org.e2ee.data.remote.users

import org.e2ee.data.remote.users.dto.RefreshResponse
import org.e2ee.data.remote.users.dto.RefreshRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface AuthApi {
    @POST("/api/v1/users/refresh")
    suspend fun refreshToken(
        @Body request: RefreshRequest
    ): Response<RefreshResponse>
}