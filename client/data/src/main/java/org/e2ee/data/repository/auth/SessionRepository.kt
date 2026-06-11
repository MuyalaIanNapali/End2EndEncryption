package org.e2ee.data.repository.auth

import android.util.Log
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteAuthRepository
import org.e2ee.data.remote.users.dto.RefreshRequest
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class SessionRepository @Inject constructor(
    private val tokenManager: TokenManager,
    private val remoteAuthRepository: RemoteAuthRepository,
    private val localUserRepository: LocalUserRepository
) {
    suspend fun autoLogin(): Boolean {

        val refreshToken = tokenManager.getRefreshToken() ?: return false

        return try {

            when (
                val result = remoteAuthRepository.refreshToken(
                    RefreshRequest(refreshToken)
                )
            ) {
                is ApiResult.Success -> {
                    val body = result.data

                    tokenManager.saveTokens(
                        accessToken = body.accessToken,
                        refreshToken = body.refreshToken
                    )
                    true
                }

                is ApiResult.Error -> {

                    tokenManager.clearTokens()
                    false
                }

                is ApiResult.NetworkError -> {
                    val localUser = localUserRepository.getUser()
                        ?: return false
                    return localUser.isLoggedIn
                }

                is ApiResult.UnknownError -> {
                    tokenManager.clearTokens()
                    false
                }
            }

        } catch (t: Throwable) {
            tokenManager.clearTokens()
            false
        }
    }

    fun logout() {
        tokenManager.clearTokens()
    }
}