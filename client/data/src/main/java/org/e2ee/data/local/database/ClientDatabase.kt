package org.e2ee.data.local.database

import androidx.room.Database
import androidx.room.RoomDatabase
import org.e2ee.data.local.opk.OneTimePreKeys
import org.e2ee.data.local.opk.OneTimePreKeysDao
import org.e2ee.data.local.ratchetStates.RatchetStates
import org.e2ee.data.local.ratchetStates.RatchetStatesDao
import org.e2ee.data.local.signedPreKeys.SignedPreKeys
import org.e2ee.data.local.signedPreKeys.SignedPreKeysDao
import org.e2ee.data.local.user.User
import org.e2ee.data.local.user.UserDao
import org.e2ee.data.local.userKeys.UserKeys
import org.e2ee.data.local.userKeys.UserKeysDao


@Database(
    entities = [
        UserKeys::class,
        OneTimePreKeys::class,
        SignedPreKeys::class,
        RatchetStates::class,
        User::class
    ],
    version = 1,
    exportSchema = false
)
public abstract class ClientDatabase: RoomDatabase() {

    abstract fun oneTimePreKeysDao(): OneTimePreKeysDao
    abstract fun userKeysDao(): UserKeysDao
    abstract fun signedPreKeysDao(): SignedPreKeysDao
    abstract fun ratchetStatesDao(): RatchetStatesDao
    abstract fun userDao(): UserDao

    companion object{
        @Volatile
        private var INSTANCE: ClientDatabase? = null

        fun getInstance(context: android.content.Context): ClientDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = androidx.room.Room.databaseBuilder(
                    context.applicationContext,
                    ClientDatabase::class.java,
                    "client_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}