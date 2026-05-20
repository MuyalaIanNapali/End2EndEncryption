package org.e2ee.data.local.user

import androidx.annotation.WorkerThread

class LocalUserRepository(
    private val dao: UserDao
) {
    @WorkerThread
    suspend fun insertUser(user: User) {
        dao.insertUser(user)
    }

    @WorkerThread
    suspend fun getUser(): User? {
        return dao.getUser()
    }

    @WorkerThread
    suspend fun deleteUser() {
        dao.deleteUser()
    }

    @WorkerThread
    suspend fun updateUser(user: User) {
        dao.updateUser(user)
    }
}