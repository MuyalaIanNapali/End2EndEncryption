package org.e2ee.data.local.remote.auth

import okhttp3.Interceptor
import okhttp3.Response

class AuthInterceptor(
    private val tokenManager: org.e2ee.data.local.remote.auth.TokenManager
): Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val accessToken = tokenManager.getAccessToken()

        val request = chain.request()
            .newBuilder()
            .apply {
               accessToken?.let {
                   addHeader("Authorization", "Bearer $it")
                }
            }
            .build()

        return chain.proceed(request)
    }

}