package org.e2ee.data.local.ratchetStates

import androidx.annotation.WorkerThread

class RatchetStatesRepository(
    private val dao: RatchetStatesDao,
) {

    @WorkerThread
    suspend fun insertRatchetState(sessionId: String,ratchetState: RatchetStateDto) {
        dao.insertRatchetState(ratchetState.toRatchetStates(sessionId))
    }

    @WorkerThread
    suspend fun deleteRatchetState(sessionId: String) {
        dao.deleteRatchetState(sessionId)
    }

    @WorkerThread
    suspend fun getRatchetStateById(id: String): RatchetStates? {
        return dao.getRatchetStateById(id)
    }

    @WorkerThread
    suspend fun updateRatchetState(sessionId: String, ratchetState: RatchetStateDto) {
        val existingState = dao.getRatchetStateById(sessionId)
        if (existingState != null) {
            val updatedState = ratchetState.toRatchetStates(sessionId)
            dao.updateRatchetState(updatedState)
        } else {
            dao.insertRatchetState(ratchetState.toRatchetStates(sessionId))
        }
    }
}