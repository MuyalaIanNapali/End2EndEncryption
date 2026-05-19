package org.e2ee.data.local.userKeys

import androidx.annotation.WorkerThread

class UserKeysRepository (
    private val dao: UserKeysDao,
){
    @WorkerThread
    suspend fun insertUserKeys(userKeys: UserKeys) {
        dao.insertUserKeys(userKeys)
    }

    @WorkerThread
    suspend fun getUserKeys(): UserKeys? {
        return dao.getUserKeys()
    }

    @WorkerThread
    suspend fun updateUserId(userId: Long) {
        dao.updateUserId(userId)
    }

    @WorkerThread
    suspend fun deleteUserKeys() {
        dao.deleteUserKeys()
    }

}