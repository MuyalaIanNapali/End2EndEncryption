package org.e2ee.data.di

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import org.e2ee.data.remote.auth.AuthInterceptor
import org.e2ee.data.remote.auth.TokenAuthenticator
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.keyManagerApi.KeyManagerApi
import org.e2ee.data.remote.network.NetworkConfig
import org.e2ee.data.remote.users.AuthApi
import org.e2ee.data.remote.users.UserApi
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideSharedPreferences(
        @ApplicationContext context: Context
    ): SharedPreferences {
        return context.getSharedPreferences(
            "e2ee_prefs",
            Context.MODE_PRIVATE
        )
    }

    @Provides
    @Singleton
    fun provideTokenManager(
        prefs: SharedPreferences
    ): TokenManager {
        return TokenManager(prefs)
    }

    @Provides
    @Singleton
    fun provideAuthApi(
        networkConfig: NetworkConfig
    ): AuthApi {
        return Retrofit.Builder()
            .baseUrl(networkConfig.baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(AuthApi::class.java)
    }

    @Provides
    @Singleton
    fun provideAuthInterceptor(
        tokenManager: TokenManager
    ): AuthInterceptor {
        return AuthInterceptor(tokenManager)
    }

    @Provides
    @Singleton
    fun provideTokenAuthenticator(
        tokenManager: TokenManager,
        authApi: AuthApi
    ): TokenAuthenticator {
        return TokenAuthenticator(
            tokenManager = tokenManager,
            authApi = authApi
        )
    }

    @Provides
    @Singleton
    fun provideOkHttpClient(
        authInterceptor: AuthInterceptor,
        tokenAuthenticator: TokenAuthenticator
    ): OkHttpClient {
        return OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .authenticator(tokenAuthenticator)
            .build()
    }

    @Provides
    @Singleton
    fun provideRetrofit(
        networkConfig: NetworkConfig,
        okHttpClient: OkHttpClient
    ): Retrofit {
        return Retrofit.Builder()
            .baseUrl(networkConfig.baseUrl)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    @Provides
    @Singleton
    fun provideUserApi(
        retrofit: Retrofit
    ): UserApi {
        return retrofit.create(UserApi::class.java)
    }

    @Provides
    @Singleton
    fun provideKeyManagerApi(
        retrofit: Retrofit
    ): KeyManagerApi {
        return retrofit.create(KeyManagerApi::class.java)
    }

    @Provides
    @Singleton
    fun provideGson(): Gson {
        return Gson()
    }
}