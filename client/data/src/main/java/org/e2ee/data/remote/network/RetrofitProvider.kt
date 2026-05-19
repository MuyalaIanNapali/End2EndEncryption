package org.e2ee.data.local.remote.network

import okhttp3.OkHttpClient
import org.e2ee.data.local.remote.auth.AuthInterceptor
import org.e2ee.data.local.remote.auth.TokenAuthenticator
import org.e2ee.data.local.remote.auth.TokenManager
import org.e2ee.data.local.remote.userApi.AuthApi
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

    fun authApi(): org.e2ee.data.local.remote.userApi.AuthApi {
        return provideAuthRetrofit().create(_root_ide_package_.org.e2ee.data.local.remote.userApi.AuthApi::class.java)
    }

    @Singleton
    fun provideRetrofit(
        tokenManager: org.e2ee.data.local.remote.auth.TokenManager
    ): Retrofit {
        val authApi = authApi()

        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(
                _root_ide_package_.org.e2ee.data.local.remote.auth.AuthInterceptor(
                    tokenManager
                )
            )
            .authenticator(
                _root_ide_package_.org.e2ee.data.local.remote.auth.TokenAuthenticator(
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