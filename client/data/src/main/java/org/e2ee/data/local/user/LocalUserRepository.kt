package org.e2ee.data.local.user

class LocalUserRepository(
    private val dao: UserDao
) {
    suspend fun insertUser(user: User) {
        dao.insertUser(user)
    }

    suspend fun getUser(): User? {
        return dao.getUser()
    }

    suspend fun deleteUser() {
        dao.deleteUser()
    }

    suspend fun updateServerId(serverId: Long) {
        dao.updateServerId(serverId)
    }

    suspend fun updateUser(user: User) {
        dao.updateUser(user)
    }


}