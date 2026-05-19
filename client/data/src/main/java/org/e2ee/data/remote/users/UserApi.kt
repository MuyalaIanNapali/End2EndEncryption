package org.e2ee.data.local.remote.userApi

import org.e2ee.data.local.remote.userApi.dto.LoginRequest
import org.e2ee.data.local.remote.userApi.dto.UpdateUserRequest
import org.e2ee.data.local.remote.userApi.dto.UserRequest
import retrofit2.Response
import retrofit2.http.GET
import org.e2ee.data.local.remote.userApi.dto.UserResponse
import retrofit2.http.Body
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

interface UserApi {
    @GET("/api/v1/users")
    suspend fun getUsers(): Response<List<org.e2ee.data.local.remote.userApi.dto.UserResponse>>

    @POST("/api/v1/users/createUser")
    suspend fun createUser(
        @Body request: org.e2ee.data.local.remote.userApi.dto.UserRequest
    ): Response<org.e2ee.data.local.remote.userApi.dto.UserResponse>

    @POST("/api/v1/users/login")
    suspend fun login(
        @Body request: org.e2ee.data.local.remote.userApi.dto.LoginRequest
    ): Response<org.e2ee.data.local.remote.userApi.dto.UserResponse>

    @GET("/api/v1/users/{username}")
    suspend fun getUserByUsername(
        @Path("username") username: String
    ): Response<org.e2ee.data.local.remote.userApi.dto.UserResponse>

    @PATCH("/api/v1/users/updateUser")
    suspend fun updateUser(
        @Body request: org.e2ee.data.local.remote.userApi.dto.UpdateUserRequest
    ): Response<Any>

    @POST("/api/v1/users/logout")
    suspend fun logout(): Response<Unit>


}