package org.e2ee.data.local.opk

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface  OneTimePreKeysDao {
    @Insert(onConflict = OnConflictStrategy.Companion.REPLACE)
    suspend fun insertOneTimePreKey(oneTimePreKey: List<OneTimePreKeys>)

    @Query("SELECT * FROM one_time_pre_keys WHERE opkId = :opkId LIMIT 1")
    suspend fun getOneTimePreKeyById(opkId: String): OneTimePreKeys?

    @Query("DELETE FROM one_time_pre_keys WHERE opkId = :opkId")
    suspend fun deleteOneTimePreKeyById(opkId: String)

    @Query("SELECT * FROM one_time_pre_keys WHERE uploaded = 0")
    suspend fun getNotUploaded(): List<OneTimePreKeys>

    @Query("UPDATE one_time_pre_keys SET uploaded = 1 WHERE opkId IN (:opkIds)")
    suspend fun markAsUploaded(opkIds: List<String>)

    @Query("SELECT COUNT(*) FROM one_time_pre_keys WHERE consumed = 0")
    suspend fun countNotConsumed(): Int

}