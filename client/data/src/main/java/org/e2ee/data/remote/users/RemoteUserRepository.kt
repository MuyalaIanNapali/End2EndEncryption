package org.e2ee.data.remote.users

import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest
import org.e2ee.data.remote.users.dto.UserResponse

class RemoteUserRepository(
    private val userApi: UserApi,
) {
    suspend fun createAccount(request: UserRequest): UserResponse {
        val response = userApi.createAccount(request)
        if (response.isSuccessful) {
            return response.body()!!
        } else {
            throw Exception("Account creation failed: ${response.code()} ${response.message()}")
        }
    }

    suspend fun login(request: LoginRequest): UserResponse{
        val response = userApi.login(request)
        if (response.isSuccessful) {
            return response.body()!!
        } else {
            throw Exception("Login failed: ${response.code()} ${response.message()}")
        }
    }

    suspend fun getUserByUsername(username: String): UserResponse {
        val response = userApi.getUserByUsername(username)
        if (response.isSuccessful) {
            return response.body()!!
        } else {
            throw Exception("Get user failed: ${response.code()} ${response.message()}")
        }
    }

    suspend fun getAllUsers(): List<UserResponse> {
        val response = userApi.getUsers()
        if (response.isSuccessful) {
            return response.body() ?: emptyList()
        } else {
            throw Exception("Get users failed: ${response.code()} ${response.message()}")
        }
    }

    suspend fun updateAccount(request: UpdateUserRequest): Any {
        val response = userApi.updateUser(request)
        if (!response.isSuccessful) {
            throw Exception("Account update failed: ${response.code()} ${response.message()}")
        }else{
            return response
        }
    }


    suspend fun logout() {
        val response = userApi.logout()
        if (!response.isSuccessful) {
            throw Exception("Logout failed: ${response.code()} ${response.message()}")
        }
    }




}