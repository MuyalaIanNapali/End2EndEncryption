package org.e2ee.data.repository

import androidx.annotation.WorkerThread
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.user.toUser
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundle
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.remote.users.dto.UserRequest

class UserRepository(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository,
    private val tokenManager: TokenManager,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository
) {

    suspend fun register(request: UserRequest): Boolean {
        var userKeys = keysRepository.getUserKeys()

        if (userKeys == null) {
            keysRepository.generateAndStoreUserKeys()
            userKeys = keysRepository.getUserKeys()
                ?: throw Exception("Failed to generate user keys")
        }

        var signedPreKey = spkRepository.getActiveSignedPreKeyBundle()

        if (signedPreKey == null) {
            spkRepository.rotateIfExpired()
            signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
                ?: throw Exception("Failed to generate signed pre key")
        }

        var opk = opkRepository.getNotUploaded()

        if (opk.isNullOrEmpty()) {
            opkRepository.generateAndStoreOPK(100)
            opk = opkRepository.getNotUploaded()
        }

        if (opk.isNullOrEmpty()) {
            throw Exception("Failed to generate one-time prekeys")
        }

        val preKeyBundle = PreKeyBundle(
            userId = null,
            identityKey = userKeys.identityKeyPublic,
            identityKeySigning = userKeys.identitySigningKeyPublic,
            signedPreKeyBundle = signedPreKey,
            opkMap = opk.associate { it.opkId to it.publicKey }
        )

        val registrationRequest = request.copy(
            preKeyBundle = preKeyBundle
        )

        val response = remoteUser.createAccount(registrationRequest)

        localUser.insertUser(
            registrationRequest.toUser().copy(
                userId = response.user.id
            )
        )

        tokenManager.saveTokens(
            response.accessToken,
            response.refreshToken
        )

        opkRepository.markAsUploaded(
            opk.map { it.opkId }
        )

        return true
    }

        suspend fun login(request: LoginRequest): Boolean {
            val response = remoteUser.login(request)


            return true
        }

}