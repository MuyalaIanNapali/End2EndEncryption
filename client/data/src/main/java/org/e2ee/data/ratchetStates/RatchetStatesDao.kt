package org.e2ee.data.ratchetStates

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import androidx.room.Upsert

@Dao
interface RatchetStatesDao {
    @Upsert
    suspend fun upsertRatchetState(ratchetState: RatchetStates)

    @Delete
    suspend fun deleteRatchetState(ratchetState: RatchetStates)

    @Update
    suspend fun insertRatchetState(ratchetState: RatchetStates)

    @Query("SELECT * FROM ratchet_states WHERE sessionId = :id ")
    suspend fun getRatchetStateById(id: String): RatchetStates?
}