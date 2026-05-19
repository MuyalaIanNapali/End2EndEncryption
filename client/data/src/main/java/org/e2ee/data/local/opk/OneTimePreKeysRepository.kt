package org.e2ee.data.local.opk

import androidx.annotation.WorkerThread
import org.e2ee.crypto.Crypto
import java.util.UUID

class OneTimePreKeysRepository(
    private val dao: OneTimePreKeysDao,
    private val crypto: Crypto
) {
    fun generateOPKId(): String {
        return "OPK_${System.currentTimeMillis()}_${UUID.randomUUID()}"
    }

    @WorkerThread
    suspend fun generateAndStoreOPK(count: Int) {
        val preKeys = (1..count).map { index ->
            val opkId = generateOPKId()
            val keyPair = crypto.generateKeyPair()
            OneTimePreKeys(opkId, keyPair.public.encoded, keyPair.private.encoded)
        }
        dao.insertOneTimePreKey(preKeys)
    }

    @WorkerThread
    suspend fun getOneTimePreKeyById(opkId: String): OneTimePreKeys? {
        return dao.getOneTimePreKeyById(opkId)
    }

    @WorkerThread
    suspend fun deleteOneTimePreKeyById(opkId: String) {
        dao.deleteOneTimePreKeyById(opkId)
    }

    @WorkerThread
    suspend fun getNotUploaded(): List<OneTimePreKeys>? {
        return dao.getNotUploaded()
    }

    @WorkerThread
    suspend fun markAsUploaded(opkIds: List<String>) {
        dao.markAsUploaded(opkIds)
    }

    @WorkerThread
    suspend fun countNotConsumed(): Int {
        return dao.countNotConsumed()
    }

}