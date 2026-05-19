package org.e2ee.data.repository

import androidx.annotation.WorkerThread
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.RemoteKeyManagerRepository
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundle
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle

class KeyManagerRepository (
    private val remoteKeyManagerRepository: RemoteKeyManagerRepository,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository,
){
    suspend fun updatePreKeyBundle(): Boolean{
        val userKeys = keysRepository.getUserKeys()
            ?: throw Exception("User keys not found")

        val signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
            ?: throw Exception("Active signed pre-key not found")

        val oneTimePreKeys = opkRepository.getNotUploaded()
            ?: throw Exception("No one-time pre-keys available")

        val preKeyBundleRequest = PreKeyBundle(
            userId = userKeys.userId,
            identityKey = userKeys.identityKeyPublic,
            signedPreKeyBundle = signedPreKey,
            identityKeySigning = userKeys.identitySigningKeyPublic,
            opkMap = oneTimePreKeys.associate { it.opkId to it.publicKey }
        )

        return remoteKeyManagerRepository.updatePreKeyBundle(preKeyBundleRequest)
    }

    suspend fun updateSignedPreKey() : Boolean {
        val userKeys = keysRepository.getUserKeys()
            ?: throw Exception("User keys not found")

        spkRepository.rotateIfExpired()

        val signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
            ?: throw Exception("Active signed pre-key not found")

        val userId = userKeys.userId
            ?: throw Exception("User server ID not found. User may not be registered.")

        return remoteKeyManagerRepository.updateSignedPreKey(
            UpdateSignedPreKeyBundle(
                userId = userId,
                keyId = signedPreKey.keyId,
                signedPreKey = signedPreKey.signedPreKey,
                signature = signedPreKey.signature
            )
        )
    }

    suspend fun updateOneTimePreKeys() : Boolean {
        val userKeys = keysRepository.getUserKeys()
            ?: throw Exception("User keys not found")

        val oneTimePreKeys = opkRepository.getNotUploaded()

        if(oneTimePreKeys.isNullOrEmpty()) {
            val count = 100 - (opkRepository.countNotConsumed())
            //generate new one-time pre-keys if none are available
            opkRepository.generateAndStoreOPK(count)
            if (count <= 0) {
                throw Exception("No uploadable OPKs available and OPK pool is already full")
            }
            return updateOneTimePreKeys() //recursively call to upload the newly generated keys
        }

        val response = remoteKeyManagerRepository.updateOneTimePreKeys(
            UpdateOpkKeys(
                userId = userKeys.userId!!,
                opkMap = oneTimePreKeys.associate { it.opkId to it.publicKey }
            )
        )

        opkRepository.markAsUploaded(
            oneTimePreKeys.map { it.opkId }
        )

        return response
    }

    @WorkerThread
    suspend fun initUserPreKeysKeys(){
        try {
            keysRepository.generateAndStoreUserKeys()

            spkRepository.rotateIfExpired()

            opkRepository.generateAndStoreOPK(100)
        }catch (e: Exception){
            // Log the error or handle it as needed
            println("Error initializing user keys: ${e.message}")
        }
    }
}