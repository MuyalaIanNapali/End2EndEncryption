package org.e2ee.client.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import org.e2ee.client.BuildConfig
import org.e2ee.data.remote.network.NetworkConfig
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppConfigModule {

    @Provides
    @Singleton
    fun provideNetworkConfig(): NetworkConfig {
        return NetworkConfig(
            baseUrl = BuildConfig.BASE_URL,
            websocketUrl = BuildConfig.WEBSOCKET_URL
        )
    }
}