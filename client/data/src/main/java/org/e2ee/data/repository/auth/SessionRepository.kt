package org.e2ee.data.repository.auth

import android.util.Log
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteAuthRepository
import org.e2ee.data.remote.users.dto.RefreshRequest
import javax.inject.Inject

class SessionRepository @Inject constructor(
    private val tokenManager: TokenManager,
    private val remoteAuthRepository: RemoteAuthRepository
) {
    suspend fun autoLogin(): Boolean {
        Log.d("SessionRepository", "Attempting auto-login...")

        val refreshToken = tokenManager.getRefreshToken()

        if (refreshToken == null) {
            Log.d("SessionRepository", "No refresh token found")
            return false
        }

        return try {
            Log.d("SessionRepository", "Calling refresh token API...")

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

                    Log.d("SessionRepository", "Auto-login successful. Tokens refreshed.")
                    true
                }

                is ApiResult.Error -> {
                    Log.d(
                        "SessionRepository",
                        "Refresh failed with status ${result.statusCode}: ${result.message}"
                    )

                    tokenManager.clearTokens()
                    Log.d("SessionRepository", "Tokens cleared after refresh failure.")

                    false
                }

                is ApiResult.NetworkError -> {
                    Log.d(
                        "SessionRepository",
                        "Refresh failed due to network error: ${result.message}"
                    )

                    false
                }

                is ApiResult.UnknownError -> {
                    Log.d(
                        "SessionRepository",
                        "Refresh failed due to unknown error: ${result.message}"
                    )

                    tokenManager.clearTokens()
                    false
                }
            }

        } catch (t: Throwable) {
            Log.e("SessionRepository", "Auto-login crashed", t)
            tokenManager.clearTokens()
            false
        }
    }

    fun logout() {
        tokenManager.clearTokens()
    }
}