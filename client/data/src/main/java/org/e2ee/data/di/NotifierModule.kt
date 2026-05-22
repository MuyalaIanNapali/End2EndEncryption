package org.e2ee.data.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import org.e2ee.data.notifications.AndroidMessageNotifier
import org.e2ee.data.repository.chat.MessageNotifier
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class NotifierModule {

    @Binds
    @Singleton
    abstract fun bindMessageNotifier(
        notifier: AndroidMessageNotifier
    ): MessageNotifier
}