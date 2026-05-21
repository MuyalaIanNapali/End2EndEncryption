package org.e2ee.data.repository.user

import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.users.RemoteUserRepository

class UserLogoutRepository(
    private val remoteUser: RemoteUserRepository,
    private val tokenManager: TokenManager
) {

    suspend fun logout() {
        try {
            remoteUser.logout()
        } catch (e: Exception) {
            println("Error during logout: ${e.message}")
        } finally {
            tokenManager.clearTokens()
        }
    }
}