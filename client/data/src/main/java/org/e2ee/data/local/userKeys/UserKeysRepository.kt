package org.e2ee.data.local.userKeys

import android.util.Log
import androidx.annotation.WorkerThread
import org.e2ee.crypto.Crypto
import javax.inject.Inject

class UserKeysRepository @Inject constructor(
    private val dao: UserKeysDao,
    private val crypto: Crypto
){
    @WorkerThread
    suspend fun insertUserKeys(userKeys: UserKeys) {
        dao.insertUserKeys(userKeys)
    }

    @WorkerThread
    suspend fun getUserKeys(): UserKeys? {
        return dao.getUserKeys()
    }

    @WorkerThread
    suspend fun updateUserId(userId: Long) {
        dao.updateUserId(userId)
    }

    @WorkerThread
    suspend fun deleteUserKeys() {
        dao.deleteUserKeys()
    }

    @WorkerThread
    suspend fun generateAndStoreUserKeys() {
        Log.d("CreateAccountDebug", "calling crypto to generate user keys")
        val (identityKeyPair, identitySigningKeyPair) = crypto.generateIKAndIKsPairs()
        Log.d("CreateAccountDebug", "crypto generated keys")
        val userKeys = UserKeys(
            identityKeyPublic = identityKeyPair.first,
            identityKeyPrivate = identityKeyPair.second,
            identitySigningKeyPublic = identitySigningKeyPair.first,
            identitySigningKeyPrivate = identitySigningKeyPair.second
        )
        insertUserKeys(userKeys)
    }

}