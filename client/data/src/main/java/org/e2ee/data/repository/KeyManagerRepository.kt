package org.e2ee.data.repository

import androidx.annotation.WorkerThread
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.RemoteKeyManagerRepository
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerification
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerificationResult
import org.e2ee.data.remote.keyManagerApi.dto.SignedPreKeyBundle
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository

class KeyManagerRepository (
    private val remoteKeyManagerRepository: RemoteKeyManagerRepository,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository,
    private val remoteUserRepository: RemoteUserRepository
){
    suspend fun updatePreKeyBundle(): ApiResult<Unit> {
        val userKeys = keysRepository.getUserKeys()
            ?: throw Exception("User keys not found")

        val signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
            ?: throw Exception("Active signed pre-key not found")

        val oneTimePreKeys = opkRepository.getNotUploaded()
            ?: throw Exception("No one-time pre-keys available")

        val preKeyBundleRequest = PreKeyBundleDto(
            userId = userKeys.userId,
            identityKey = userKeys.identityKeyPublic,
            signedPreKeyBundle = signedPreKey,
            identityKeySigning = userKeys.identitySigningKeyPublic,
            opkMap = oneTimePreKeys.associate { it.opkId to it.publicKey }
        )

        return remoteKeyManagerRepository.updatePreKeyBundle(preKeyBundleRequest)
    }

    suspend fun updateSignedPreKey() : ApiResult<Unit> {
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

    suspend fun updateOneTimePreKeys() : ApiResult<Unit> {
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
    suspend fun initUserPreKeys(){
        try {
            keysRepository.generateAndStoreUserKeys()

            spkRepository.rotateIfExpired()

            opkRepository.generateAndStoreOPK(100)
        }catch (e: Exception){
            // Log the error or handle it as needed
            println("Error initializing user keys: ${e.message}")
        }
    }

    fun verifyOwnServerPreKeys(
        server: PreKeyVerification,
        localIdentitySigningPublicKey: ByteArray,
        localSignedPreKeyBundle: SignedPreKeyBundle,
        verifySignature: (
            publicKey: ByteArray,
            message: ByteArray,
            signature: ByteArray
        ) -> Boolean
    ): PreKeyVerificationResult {

        val identitySigningKeyMatches =
            server.identityKeySigning.contentEquals(localIdentitySigningPublicKey)

        val signedPreKeyIdMatches =
            server.signedPreKeyBundle.keyId == localSignedPreKeyBundle.keyId

        val signedPreKeyMatches =
            server.signedPreKeyBundle.signedPreKey.contentEquals(
                localSignedPreKeyBundle.signedPreKey
            )

        val signatureValid = verifySignature(
            server.identityKeySigning,
            server.signedPreKeyBundle.signedPreKey,
            server.signedPreKeyBundle.signature
        )

        val isValid =
            identitySigningKeyMatches &&
                    signedPreKeyIdMatches &&
                    signedPreKeyMatches &&
                    signatureValid

        return PreKeyVerificationResult(
            isValid = isValid,
            identitySigningKeyMatches = identitySigningKeyMatches,
            signedPreKeyMatches = signedPreKeyMatches,
            signedPreKeyIdMatches = signedPreKeyIdMatches,
            signatureValid = signatureValid
        )
    }

}