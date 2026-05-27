package org.e2ee.data.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import org.e2ee.data.repository.user.UserRepository
import org.e2ee.domain.repository.AuthRepository
import org.e2ee.domain.repository.UserRepository as UserRepositoryContract
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindAuthRepository(
        userRepository: UserRepository
    ): AuthRepository

    @Binds
    @Singleton
    abstract fun bindUserRepository(
        userRepository: UserRepository
    ): UserRepositoryContract
}