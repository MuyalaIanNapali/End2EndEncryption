package org.e2ee.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import org.e2ee.domain.DatabasePrewarmer

@Module
@InstallIn(SingletonComponent::class)
abstract class DatabaseModule {

    @Binds
    @Singleton
    abstract fun bindDatabasePrewarmer(impl: DatabasePrewarmerImpl): DatabasePrewarmer
}

