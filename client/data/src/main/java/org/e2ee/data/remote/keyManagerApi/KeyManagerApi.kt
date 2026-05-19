package org.e2ee.data.remote.keyManagerApi

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundle
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle
import retrofit2.Response
import retrofit2.http.POST

interface KeyManagerApi {
    @POST("/api/v1/keymanager/updateSignedPreKey")
    suspend fun updateSignedPreKey(request: UpdateSignedPreKeyBundle): Response<Unit>

    @POST("/api/v1/keymanager/updateOPK")
    suspend fun updateOneTimePreKeys(request: UpdateOpkKeys): Response<Unit>

    @POST("/api/v1/keymanager/updatePreKeyBundle")
    suspend fun updatePreKeyBundle(request: PreKeyBundle): Response<Unit>
}