package org.e2ee.data.di

import android.content.Context
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
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
        // Load the native library eagerly but off the calling thread — this is
        // safe to call multiple times (it's a no-op after the first load).
        // The actual key derivation and database open happen on IO dispatcher.
        System.loadLibrary("sqlcipher")

        val passphrase = databaseKeyManager.getOrCreateDatabaseKey()

        val factory = SupportOpenHelperFactory(
            passphrase,
            null,
            false
        )

        // Build the Room database object — this is cheap and does NOT open the
        // underlying SQLite file. Room opens lazily on first DAO access.
        // We intentionally remove the eager SELECT 1 verification: if the key
        // is wrong, the first real DAO call will throw and can be handled there.
        return try {
            Room.databaseBuilder(
                context,
                ClientDatabase::class.java,
                DATABASE_NAME
            )
                .openHelperFactory(factory)
                .fallbackToDestructiveMigration(false)
                .build()
        } catch (e: Exception) {
            // Key mismatch on a fresh build — reset and retry once
            databaseKeyManager.resetDatabaseCompletely()
            val freshPassphrase = databaseKeyManager.getOrCreateDatabaseKey()
            val freshFactory = SupportOpenHelperFactory(freshPassphrase, null, false)
            Room.databaseBuilder(
                context,
                ClientDatabase::class.java,
                DATABASE_NAME
            )
                .openHelperFactory(freshFactory)
                .fallbackToDestructiveMigration(false)
                .build()
        }
    }

    @Provides
    fun provideUserKeysDao(database: ClientDatabase): UserKeysDao = database.userKeysDao()

    @Provides
    fun provideOneTimePreKeysDao(database: ClientDatabase): OneTimePreKeysDao = database.oneTimePreKeysDao()

    @Provides
    fun provideSignedPreKeysDao(database: ClientDatabase): SignedPreKeysDao = database.signedPreKeysDao()

    @Provides
    fun provideRatchetStatesDao(database: ClientDatabase): RatchetStatesDao = database.ratchetStatesDao()

    @Provides
    fun provideUserDao(database: ClientDatabase): UserDao = database.userDao()

    @Provides
    fun provideFriendsDao(database: ClientDatabase): FriendsDao = database.friendsDao()

    @Provides
    fun provideChatRoomDao(database: ClientDatabase): ChatRoomDao = database.chatRoomDao()

    @Provides
    fun provideMessagesDao(database: ClientDatabase): MessagesDao = database.messagesDao()
}