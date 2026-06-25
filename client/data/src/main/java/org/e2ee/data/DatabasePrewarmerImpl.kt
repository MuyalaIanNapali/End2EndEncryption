package org.e2ee.data

import javax.inject.Inject
import javax.inject.Singleton
import org.e2ee.data.local.database.ClientDatabase
import org.e2ee.domain.DatabasePrewarmer

/** Implementation kept in the data module so it can reference Room/ClientDatabase. */
@Singleton
class DatabasePrewarmerImpl @Inject constructor(
    private val database: ClientDatabase
) : DatabasePrewarmer {

    override fun preWarm() {
        try {
            // Access the DB to force initialization. Implementations may vary
            // depending on Room version; this uses the openHelper which is
            // available inside the data module classpath.
            database.openHelper.writableDatabase.query("SELECT 1").close()
        } catch (_: Throwable) {
            // Ignore errors during pre-warm — the app can still proceed.
        }
    }
}

