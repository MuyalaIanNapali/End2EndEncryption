package org.e2ee.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import org.e2ee.data.opk.OneTimePreKeysDao
import org.e2ee.data.opk.OneTimePreKeys
import org.e2ee.data.ratchetStates.RatchetStates
import org.e2ee.data.ratchetStates.RatchetStatesDao
import org.e2ee.data.signedPreKeys.SignedPreKeys
import org.e2ee.data.signedPreKeys.SignedPreKeysDao
import org.e2ee.data.userKeys.UserKeys
import org.e2ee.data.userKeys.UserKeysDao

@Database(
    entities = [
        OneTimePreKeys::class,
        UserKeys::class,
        SignedPreKeys::class,
        RatchetStates::class
    ],
    version = 1,
    exportSchema = false
)
public abstract class ClientDatabase: RoomDatabase() {

    abstract fun oneTimePreKeysDao(): OneTimePreKeysDao
    abstract fun userKeysDao(): UserKeysDao
    abstract fun signedPreKeysDao(): SignedPreKeysDao
    abstract fun ratchetStatesDao(): RatchetStatesDao

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