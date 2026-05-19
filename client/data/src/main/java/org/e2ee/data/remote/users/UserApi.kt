package org.e2ee.data.remote.users

import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.remote.users.dto.LoginResponse
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest
import retrofit2.Response
import retrofit2.http.GET
import org.e2ee.data.remote.users.dto.UserResponse
import retrofit2.http.Body
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

interface UserApi {
    @GET("/api/v1/users")
    suspend fun getUsers(): Response<List<UserResponse>>

    @POST("/api/v1/users/createUser")
    suspend fun createAccount(
        @Body request: UserRequest
    ): Response<LoginResponse>

    @POST("/api/v1/users/login")
    suspend fun login(
        @Body request: LoginRequest
    ): Response<LoginResponse>

    @GET("/api/v1/users/{username}")
    suspend fun getUserByUsername(
        @Path("username") username: String
    ): Response<UserResponse>

    @PATCH("/api/v1/users/updateUser")
    suspend fun updateUser(
        @Body request: UpdateUserRequest
    ): Response<Unit>

    @POST("/api/v1/users/logout")
    suspend fun logout(): Response<Unit>


}