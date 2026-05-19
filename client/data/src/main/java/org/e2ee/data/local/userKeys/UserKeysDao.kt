package org.e2ee.data.local.userKeys

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface UserKeysDao {
    @Upsert
    suspend fun insertUserKeys(userKeys: UserKeys)

    @Query("SELECT * FROM user_keys")
    suspend fun getUserKeys(): UserKeys?

    @Query("UPDATE user_keys SET userId = :userId WHERE id = 1")
    suspend fun updateUserId(userId: Long)

    @Query("DELETE FROM user_keys WHERE id = 1")
    suspend fun deleteUserKeys()

}