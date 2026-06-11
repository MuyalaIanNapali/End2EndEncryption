package org.e2ee.data.di

import android.content.Context
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.e2ee.data.local.chatRoom.ChatRoomDao
import org.e2ee.data.local.database.ClientDatabase
import org.e2ee.data.local.friends.FriendsDao
import org.e2ee.data.local.messages.MessagesDao
import org.e2ee.data.local.opk.OneTimePreKeysDao
import org.e2ee.data.local.ratchetStates.RatchetStatesDao
import org.e2ee.data.local.signedPreKeys.SignedPreKeysDao
import org.e2ee.data.local.user.UserDao
import org.e2ee.data.local.userKeys.UserKeysDao
import org.e2ee.data.security.DatabaseKeyManager
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    private const val DATABASE_NAME = "client_database"

    @Provides
    @Singleton
    fun provideClientDatabase(
        @ApplicationContext context: Context,
        databaseKeyManager: DatabaseKeyManager
    ): ClientDatabase {
        System.loadLibrary("sqlcipher")

        return try {
            buildAndOpenDatabase(context, databaseKeyManager)
        } catch (e: Exception) {
            databaseKeyManager.resetDatabaseCompletely()
            buildAndOpenDatabase(context, databaseKeyManager)
        }
    }

    private fun buildAndOpenDatabase(
        context: Context,
        databaseKeyManager: DatabaseKeyManager
    ): ClientDatabase {
        val passphrase = databaseKeyManager.getOrCreateDatabaseKey()

        val factory = SupportOpenHelperFactory(
            passphrase,
            null,
            false
        )

        val database = Room.databaseBuilder(
            context,
            ClientDatabase::class.java,
            DATABASE_NAME
        )
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration(false)
            .build()

        try {
            database.openHelper.writableDatabase.query("SELECT 1").close()
        } catch (e: Exception) {
            database.close()
            throw e
        }

        return database
    }

    @Provides
    fun provideUserKeysDao(database: ClientDatabase): UserKeysDao {
        return database.userKeysDao()
    }

    @Provides
    fun provideOneTimePreKeysDao(database: ClientDatabase): OneTimePreKeysDao {
        return database.oneTimePreKeysDao()
    }

    @Provides
    fun provideSignedPreKeysDao(database: ClientDatabase): SignedPreKeysDao {
        return database.signedPreKeysDao()
    }

    @Provides
    fun provideRatchetStatesDao(database: ClientDatabase): RatchetStatesDao {
        return database.ratchetStatesDao()
    }

    @Provides
    fun provideUserDao(database: ClientDatabase): UserDao {
        return database.userDao()
    }

    @Provides
    fun provideFriendsDao(database: ClientDatabase): FriendsDao {
        return database.friendsDao()
    }

    @Provides
    fun provideChatRoomDao(database: ClientDatabase): ChatRoomDao {
        return database.chatRoomDao()
    }

    @Provides
    fun provideMessagesDao(database: ClientDatabase): MessagesDao {
        return database.messagesDao()
    }
}