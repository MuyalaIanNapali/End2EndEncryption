package org.e2ee.domain

/**
 * Simple interface that allows the app module to request a database pre-warm
 * without referencing Room/ClientDatabase types at compile time.
 */
interface DatabasePrewarmer {
    /**
     * Pre-warm the database (synchronously). Implementations should catch
     * and ignore any exceptions they don't want to propagate to the caller.
     */
    fun preWarm()
}

