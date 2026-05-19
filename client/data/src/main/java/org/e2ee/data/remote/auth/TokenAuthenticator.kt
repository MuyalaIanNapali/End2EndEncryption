package org.e2ee.data.local.remote.auth

import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.Route
import okhttp3.Response
import okhttp3.Request
import org.e2ee.data.local.remote.userApi.AuthApi
import org.e2ee.data.local.remote.userApi.dto.RefreshRequest

class TokenAuthenticator(
    private val tokenManager: org.e2ee.data.local.remote.auth.TokenManager,
    private val authApi: org.e2ee.data.local.remote.userApi.AuthApi
) : Authenticator{
    override fun authenticate(
        route: Route?,
        response: Response
    ): Request?{
        synchronized(this){
            if (
                response.request.url.encodedPath.contains("/api/v1/users/refresh")
            ){
                return null
            }

            val refresh = tokenManager.getRefreshToken() ?: return null

            val refreshResponse = runBlocking {
                authApi.refreshToken(
                    _root_ide_package_.org.e2ee.data.local.remote.userApi.dto.RefreshRequest(refresh)
                )
            }

            if (!refreshResponse.isSuccessful){
                tokenManager.clearTokens()
                return null
            }

            val body = refreshResponse.body() ?: return null

            tokenManager.saveAccessToken(body.accessToken)
            tokenManager.saveRefreshToken(body.refreshToken)

            return response.request.newBuilder()
                .header("Authorization", "Bearer ${body.accessToken}")
                .build()
        }
    }
}