package org.e2ee.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import org.e2ee.data.opk.OneTimePreKeysDao
import org.e2ee.data.opk.OneTimePreKeys
import org.e2ee.data.signedPreKeys.SignedPreKeys
import org.e2ee.data.userKeys.UserKeys

@Database(
    entities = [
        OneTimePreKeys::class,
        UserKeys::class,
        SignedPreKeys::class
               ],
    version = 1,
    exportSchema = false
)
abstract class ClientDatabase: RoomDatabase() {

    abstract val oneTimePreKeysDao: OneTimePreKeysDao

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