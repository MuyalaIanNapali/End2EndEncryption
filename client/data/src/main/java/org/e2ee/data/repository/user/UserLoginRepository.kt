package org.e2ee.data.repository.user

import android.util.Log
import org.e2ee.crypto.Crypto
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.LoginRequestDto
import org.e2ee.data.repository.keys.KeyManagerRepository
import org.e2ee.data.repository.keys.UserPreKeyInitializer
import org.e2ee.domain.model.DomainResult
import javax.inject.Inject

class UserLoginRepository @Inject constructor(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository,
    private val tokenManager: TokenManager,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val keyManagerRepository: KeyManagerRepository,
    private val crypto: Crypto,
    private val userPreKeyInitializer: UserPreKeyInitializer
) {

    suspend fun login(request: LoginRequestDto): DomainResult<Boolean> {
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

                    when(ensureLocalKeysExist()) {
                        is DomainResult.Success ->{
                            val localKeys = keysRepository.getUserKeys()
                                ?: return DomainResult
                                    .Error("Failed to retrieve local keys after login")

                            val localSpk = spkRepository.getActiveSignedPreKeyBundle()
                                ?: return DomainResult
                                    .Error(
                                        "Failed to retrieve local signed pre-key bundle after login"
                                    )

                            val serverVerification = loginResponse.preKeyVerification

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
                                val success = uploadFullPreKeyBundle()
                                return if (success) {
                                    DomainResult.Success(true)
                                } else {
                                    DomainResult.Error("Failed to upload pre-key bundle. Please try logging in again.")
                                }
                            }
                        }
                        is DomainResult.Error -> Log.e("Login", "Error ensuring local keys: ${(ensureLocalKeysExist() as DomainResult.Error).message}")
                        else -> DomainResult.Error("Unexpected result while ensuring local keys exist during login.")
                    }

                    DomainResult.Success(true)
                }

                is ApiResult.Error -> DomainResult.Error(response.message)
                is ApiResult.NetworkError -> DomainResult.Error("Network error. Please check your connection and try again.")
                is ApiResult.UnknownError -> DomainResult.Error(response.message )
            }
        } catch (e: Exception) {
            DomainResult.Error(e.message ?: "An unexpected error occurred. Please try again.")
        }
    }

    private suspend fun ensureLocalKeysExist(): DomainResult<Boolean> {
        var localKeys = keysRepository.getUserKeys()
        var localSpk = spkRepository.getActiveSignedPreKeyBundle()

        if (localKeys != null && localSpk != null) {
            //update userid in local keys if not set
            if (localKeys.userId == null) {
                val user = localUser.getUser()
                if (user != null) {
                    keysRepository.updateUserId(user.userId)
                } else {
                    return DomainResult.Error("User data not found locally. Please try logging in again.")
                }
                return DomainResult.Success(true)
            }
        }

        if (keyManagerRepository.initUserPreKeys()) {
            localKeys = keysRepository.getUserKeys()
            localSpk = spkRepository.getActiveSignedPreKeyBundle()

            if (localKeys == null || localSpk == null) {
                return DomainResult.Error("Failed to initialize local keys. Please try logging in again.")
            } else {
                val user = localUser.getUser()
                    ?: return DomainResult.Error("User data not found locally after initializing keys. Please try logging in again.")
                keysRepository.updateUserId(user.userId)

            }
            return DomainResult.Success(true)
        } else {
            return DomainResult.Error("Failed to initialize user pre-keys. Please try logging in again.")
        }

        /*
    val uploaded = uploadFullPreKeyBundle()

    return if (uploaded) {
        DomainResult.Success(true)
    } else {
        DomainResult.Error("Failed to upload pre-key bundle. Please try logging in again.")
    }

     */
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