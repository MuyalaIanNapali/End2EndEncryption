package org.e2ee.data.repository.user

import org.e2ee.crypto.Crypto
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.user.toUser
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.repository.keys.KeyManagerRepository

class UserLoginRepository(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository,
    private val tokenManager: TokenManager,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val keyManagerRepository: KeyManagerRepository,
    private val crypto: Crypto
) {

    suspend fun login(request: LoginRequest): Boolean {
        return try {
            when (val response = remoteUser.login(request)) {
                is ApiResult.Success -> {
                    val loginResponse = response.data

                    tokenManager.saveTokens(
                        accessToken = loginResponse.accessToken,
                        refreshToken = loginResponse.refreshToken
                    )

                    localUser.insertUser(
                        loginResponse.user.toUser()
                    )

                    ensureLocalKeysExist() ?: return false

                    val localKeys = keysRepository.getUserKeys()
                        ?: return false

                    val localSpk = spkRepository.getActiveSignedPreKeyBundle()
                        ?: return false

                    val serverVerification = loginResponse.preKeyVerification

                    if (serverVerification == null) {
                        return uploadFullPreKeyBundle()
                    }

                    val result = keyManagerRepository.verifyOwnServerPreKeys(
                        server = serverVerification,
                        localIdentitySigningPublicKey = localKeys.identitySigningKeyPublic,
                        localSignedPreKeyBundle = localSpk,
                        verifySignature = { publicKey, message, signature ->
                            crypto.verifySignature(
                                publicKey = publicKey,
                                message = message,
                                signature = signature
                            )
                        }
                    )

                    if (!result.isValid) {
                        return uploadFullPreKeyBundle()
                    }

                    true
                }

                is ApiResult.Error -> false
                is ApiResult.NetworkError -> false
                is ApiResult.UnknownError -> false
            }
        } catch (e: Exception) {
            false
        }
    }

    private suspend fun ensureLocalKeysExist(): Boolean? {
        var localKeys = keysRepository.getUserKeys()
        var localSpk = spkRepository.getActiveSignedPreKeyBundle()

        if (localKeys != null && localSpk != null) {
            return true
        }

        val initialized = keyManagerRepository.initUserPreKeys()

        if (!initialized) {
            return null
        }

        localKeys = keysRepository.getUserKeys()
        localSpk = spkRepository.getActiveSignedPreKeyBundle()

        if (localKeys == null || localSpk == null) {
            return null
        }

        val uploaded = uploadFullPreKeyBundle()

        return if (uploaded) true else null
    }

    private suspend fun uploadFullPreKeyBundle(): Boolean {
        return when (keyManagerRepository.updatePreKeyBundle()) {
            is ApiResult.Success -> true
            is ApiResult.Error -> false
            is ApiResult.NetworkError -> false
            is ApiResult.UnknownError -> false
        }
    }
}