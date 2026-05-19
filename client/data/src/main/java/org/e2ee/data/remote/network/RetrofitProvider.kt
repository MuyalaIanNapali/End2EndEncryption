package org.e2ee.data.remote.network

import okhttp3.OkHttpClient
import org.e2ee.data.remote.auth.AuthInterceptor
import org.e2ee.data.remote.auth.TokenAuthenticator
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.users.AuthApi
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import javax.inject.Singleton

object RetrofitProvider {
    private const val BASE_URL = "http://46.96.32.74:5000/"

    private fun provideAuthRetrofit(): Retrofit {
        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    fun authApi(): AuthApi {
        return provideAuthRetrofit().create(AuthApi::class.java)
    }

    @Singleton
    fun provideRetrofit(
        tokenManager: TokenManager
    ): Retrofit {
        val authApi = authApi()

        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(
                AuthInterceptor(
                    tokenManager
                )
            )
            .authenticator(
                TokenAuthenticator(
                    tokenManager,
                    authApi
                )
            )
            .build()

        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }
}