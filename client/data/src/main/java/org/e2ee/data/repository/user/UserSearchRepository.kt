package org.e2ee.data.repository.user

import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository

class UserSearchRepository(
    private val remoteUser: RemoteUserRepository
) {

    suspend fun searchAllUsers(): ApiResult<List<String>> {
        return try {
            when (val response = remoteUser.getAllUsers()) {
                is ApiResult.Success -> {
                    val usernames = response.data.map { it.username }
                    ApiResult.Success(usernames)
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to fetch users")
        }
    }

    suspend fun searchByUsername(username: String): ApiResult<String> {
        return try {
            when (val response = remoteUser.getUserByUsername(username)) {
                is ApiResult.Success -> {
                    ApiResult.Success(response.data.username)
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to fetch user")
        }
    }
}