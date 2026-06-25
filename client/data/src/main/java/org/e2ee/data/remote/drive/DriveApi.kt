package org.e2ee.data.remote.drive

import okhttp3.MultipartBody
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part

interface DriveApi {

    @Multipart
    @POST(
        "upload/drive/v3/files?uploadType=multipart"
    )
    suspend fun uploadBackup(
        @Header("Authorization")
        authorization: String,

        @Part metadata: MultipartBody.Part,

        @Part file: MultipartBody.Part
    )
}