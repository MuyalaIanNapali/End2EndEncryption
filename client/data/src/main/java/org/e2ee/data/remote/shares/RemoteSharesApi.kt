package org.e2ee.data.remote.shares

import org.e2ee.data.remote.shares.dto.ShareResponse
import org.e2ee.data.remote.shares.dto.UpdateSharesRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PUT

interface RemoteSharesApi {
    @GET("api/v1/share")
    suspend fun getUserShare(): Response<ShareResponse>

    @PUT("api/v1/share")
    suspend fun updateUserShare(
        @Body request: UpdateSharesRequest
    ): Response<Unit>

}