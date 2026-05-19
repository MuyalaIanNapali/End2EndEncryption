package org.e2ee.data.local.ratchetStates

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

@Dao
interface RatchetStatesDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRatchetState(ratchetState: RatchetStates)

    @Query("DELETE FROM ratchet_states WHERE sessionId = :sessionId")
    suspend fun deleteRatchetState(sessionId: String)

    @Update
    suspend fun updateRatchetState(ratchetState: RatchetStates)

    @Query("SELECT * FROM ratchet_states WHERE sessionId = :id ")
    suspend fun getRatchetStateById(id: String): RatchetStates?
}