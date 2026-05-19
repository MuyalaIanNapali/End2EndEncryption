package org.e2ee.data.local.user

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Update
import androidx.room.Upsert

@Dao
interface UserDao {
    @Upsert
    suspend fun insertUser(user: User)

    @Query("SELECT * FROM user WHERE localId = 1")
    suspend fun getUser(): User?

    @Query("DELETE FROM user WHERE localId = 1")
    suspend fun deleteUser()

    @Query("UPDATE user SET id = :serverId WHERE localId = 1")
    suspend fun updateServerId(serverId: Long)

    @Update
    suspend fun updateUser(user: User)

    @Query("UPDATE user SET userId= :serverId WHERE localId = 1")
    suspend fun updateUserServerId(serverId: Long)

}