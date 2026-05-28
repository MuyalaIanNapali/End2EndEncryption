package org.e2ee.data.repository.user

import android.util.Log
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.domain.model.RemoteUserDetails
import javax.inject.Inject

class UserSearchRepository @Inject constructor(
    private val remoteUser: RemoteUserRepository
) {

    suspend fun searchAllUsers(): ApiResult<List<RemoteUserDetails>> {
        return try {
            when (val response = remoteUser.getAllUsers()) {
                is ApiResult.Success -> {
                    ApiResult.Success(response.data.map { it.toRemoteUserDetails() })
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to fetch users")
        }
    }

    suspend fun searchByUsername(username: String): ApiResult<RemoteUserDetails> {
        return try {
            when (val response = remoteUser.getUserByUsername(username)) {
                is ApiResult.Success -> {
                    ApiResult.Success(response.data.toRemoteUserDetails())
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to fetch user")
        }
    }

    suspend fun searchUsersByUsername(username: String): ApiResult<List<RemoteUserDetails>> {
        Log.d("search", "Searching suspend for users with username: $username")
        return try {
            when (val response = remoteUser.searchByUsername(username)) {
                is ApiResult.Success -> {
                    ApiResult.Success(response.data.map { it.toRemoteUserDetails() })
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to search users")
        }
    }
}