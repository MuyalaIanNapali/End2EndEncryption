package org.e2ee.data.repository.user

import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.user.toUser
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.UpdateUserRequest

class UserAccountRepository(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository
) {

    suspend fun updateAccountInfo(
        request: UpdateUserRequest
    ): ApiResult<Unit> {
        return try {
            val currentUser = localUser.getUser()
                ?: return ApiResult.UnknownError("Failed to retrieve local user info")

            when (val response = remoteUser.updateAccount(request)) {
                is ApiResult.Success -> {
                    localUser.updateUser(
                        request.toUser(currentUser)
                    )

                    ApiResult.Success(Unit)
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to update account info")
        }
    }
}