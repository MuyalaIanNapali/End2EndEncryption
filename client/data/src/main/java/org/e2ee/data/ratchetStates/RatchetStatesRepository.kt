package org.e2ee.data.ratchetStates

import androidx.annotation.WorkerThread

class RatchetStatesRepository(
    private val dao: RatchetStatesDao,
) {

    @WorkerThread
    suspend fun upsertRatchetState(ratchetState: RatchetStates) {
        dao.upsertRatchetState(ratchetState)
    }

    @WorkerThread
    suspend fun deleteRatchetState(ratchetState: RatchetStates) {
        dao.deleteRatchetState(ratchetState)
    }

    @WorkerThread
    suspend fun insertRatchetState(ratchetState: RatchetStates) {
        dao.insertRatchetState(ratchetState)
    }

    @WorkerThread
    suspend fun getRatchetStateById(id: String): RatchetStates? {
        return dao.getRatchetStateById(id)
    }
}