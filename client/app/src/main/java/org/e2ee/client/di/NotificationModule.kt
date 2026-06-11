package org.e2ee.client.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import org.e2ee.client.notifications.AndroidMessageNotifier
import org.e2ee.domain.notifications.MessageNotifier
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class NotificationModule {

    @Binds
    @Singleton
    abstract fun bindMessageNotifier(
        androidMessageNotifier: AndroidMessageNotifier
    ): MessageNotifier
}