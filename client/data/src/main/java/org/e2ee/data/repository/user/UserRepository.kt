package org.e2ee.data.repository.user

import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest

class UserRepository(
    private val userRegistrationRepository: UserRegistrationRepository,
    private val userLoginRepository: UserLoginRepository,
    private val userAccountRepository: UserAccountRepository,
    private val userLogoutRepository: UserLogoutRepository,
    private val userSearchRepository: UserSearchRepository
) {

    suspend fun register(request: UserRequest): ApiResult<Boolean> {
        return userRegistrationRepository.register(request)
    }

    suspend fun login(request: LoginRequest): Boolean {
        return userLoginRepository.login(request)
    }

    suspend fun updateAccountInfo(
        request: UpdateUserRequest
    ): ApiResult<Unit> {
        return userAccountRepository.updateAccountInfo(request)
    }

    suspend fun logout() {
        userLogoutRepository.logout()
    }

    suspend fun searchAllUsers(): ApiResult<List<String>> {
        return userSearchRepository.searchAllUsers()
    }

    suspend fun searchByUsername(username: String): ApiResult<String> {
        return userSearchRepository.searchByUsername(username)
    }
}