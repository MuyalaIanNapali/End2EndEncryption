package org.e2ee.data.remote.users

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleResponse
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.network.safeApiCall
import org.e2ee.data.remote.users.dto.LoginRequestDto
import org.e2ee.data.remote.users.dto.LoginResponse
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest
import org.e2ee.data.remote.users.dto.UserRequestDto
import org.e2ee.data.remote.users.dto.UserResponse
import javax.inject.Inject

class RemoteUserRepository @Inject constructor(
    private val userApi: UserApi,
) {
    suspend fun createAccount(request: UserRequestDto): ApiResult<LoginResponse> {
        return safeApiCall {
            userApi.createAccount(request)
        }
    }

    suspend fun login(request: LoginRequestDto): ApiResult<LoginResponse> {
        return safeApiCall {
            userApi.login(request)
        }
    }

    suspend fun getUserByUsername(username: String): ApiResult<UserResponse> {
        return safeApiCall {
            userApi.getUserByUsername(username)
        }
    }

    suspend fun getUserByUserId(userId : Long): ApiResult<UserResponse> {
        return safeApiCall {
            userApi.getUserByUserId(userId)
        }
    }

    suspend fun getAllUsers(): ApiResult<List<UserResponse>> {
         return safeApiCall {
             userApi.getUsers()
         }
    }

    suspend fun updateAccount(request: UpdateUserRequest): ApiResult<Unit> {
        return safeApiCall { userApi.updateUser(request)}
    }


    suspend fun logout() {
        safeApiCall { userApi.logout() }
    }

    suspend fun getUserPreKeys(username: String): ApiResult<PreKeyBundleResponse> {
        return safeApiCall { userApi.getUserPublicKeys(username) }
    }
}