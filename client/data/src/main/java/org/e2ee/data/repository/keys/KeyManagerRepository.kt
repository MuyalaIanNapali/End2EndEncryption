package org.e2ee.data.repository.keys

import androidx.annotation.WorkerThread
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerification
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerificationResult
import org.e2ee.data.remote.keyManagerApi.dto.SignedPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import javax.inject.Inject

class KeyManagerRepository @Inject constructor(
    private val userPreKeyInitializer: UserPreKeyInitializer,
    private val preKeyBundleUploader: PreKeyBundleUploader,
    private val signedPreKeyUploader: SignedPreKeyUploader,
    private val oneTimePreKeyUploader: OneTimePreKeyUploader,
    private val ownPreKeyVerifier: OwnPreKeyVerifier
) {

    suspend fun updatePreKeyBundle(): ApiResult<Unit> {
        return preKeyBundleUploader.updatePreKeyBundle()
    }

    suspend fun updateSignedPreKey(): ApiResult<Unit> {
        return signedPreKeyUploader.updateSignedPreKey()
    }

    suspend fun updateOneTimePreKeys(): ApiResult<Unit> {
        return oneTimePreKeyUploader.updateOneTimePreKeys()
    }

    @WorkerThread
    suspend fun initUserPreKeys(): Boolean {
        return userPreKeyInitializer.initUserPreKeys()
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
        return ownPreKeyVerifier.verifyOwnServerPreKeys(
            server = server,
            localIdentitySigningPublicKey = localIdentitySigningPublicKey,
            localSignedPreKeyBundle = localSignedPreKeyBundle,
            verifySignature = verifySignature
        )
    }
}