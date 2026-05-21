package org.e2ee.data.repository

import org.e2ee.crypto.Crypto
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.user.toUser
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.LoginRequest
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest

class UserRepository(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository,
    private val tokenManager: TokenManager,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository,
    private val keyManagerRepository: KeyManagerRepository,
    private val crypto: Crypto
) {

    suspend fun register(request: UserRequest): ApiResult<Boolean> {
        return try {
            var userKeys = keysRepository.getUserKeys()

            if (userKeys == null) {
                keysRepository.generateAndStoreUserKeys()
                userKeys = keysRepository.getUserKeys()
                    ?: return ApiResult.UnknownError("Failed to generate user keys")
            }

            var signedPreKey = spkRepository.getActiveSignedPreKeyBundle()

            if (signedPreKey == null) {
                spkRepository.rotateIfExpired()
                signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
                    ?: return ApiResult.UnknownError("Failed to generate signed pre-key")
            }

            var opk = opkRepository.getNotUploaded()

            if (opk.isNullOrEmpty()) {
                opkRepository.generateAndStoreOPK(100)
                opk = opkRepository.getNotUploaded()
            }

            if (opk.isNullOrEmpty()) {
                return ApiResult.UnknownError("Failed to generate one-time preKeys")
            }

            val preKeyBundle = PreKeyBundleDto(
                userId = null,
                identityKey = userKeys.identityKeyPublic,
                identityKeySigning = userKeys.identitySigningKeyPublic,
                signedPreKeyBundle = signedPreKey,
                opkMap = opk.associate { it.opkId to it.publicKey }
            )

            val registrationRequest = request.copy(
                preKeyBundle = preKeyBundle
            )

            when (val response = remoteUser.createAccount(registrationRequest)) {
                is ApiResult.Success -> {
                    val loginResponse = response.data

                    tokenManager.saveTokens(
                        accessToken = loginResponse.accessToken,
                        refreshToken = loginResponse.refreshToken
                    )

                    localUser.insertUser(
                        loginResponse.user.toUser()
                    )

                    opkRepository.markAsUploaded(
                        opk.map { it.opkId }
                    )

                    ApiResult.Success(true)
                }

                is ApiResult.Error -> {
                    response
                }

                is ApiResult.NetworkError -> {
                    response
                }

                is ApiResult.UnknownError -> {
                    response
                }
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Registration failed")
        }
    }
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

                    var localKeys = keysRepository.getUserKeys()
                    var localSPK = spkRepository.getActiveSignedPreKeyBundle()

                    if (localKeys == null || localSPK == null) {
                        keyManagerRepository.initUserPreKeys()

                        localKeys = keysRepository.getUserKeys()
                        localSPK = spkRepository.getActiveSignedPreKeyBundle()

                        if (localKeys == null || localSPK == null) {
                            return false
                        }

                        return when (keyManagerRepository.updatePreKeyBundle()) {
                            is ApiResult.Success -> true
                            is ApiResult.Error -> false
                            is ApiResult.NetworkError -> false
                            is ApiResult.UnknownError -> false
                        }
                    }

                    val serverVerification = loginResponse.preKeyVerification
                        ?: return when (keyManagerRepository.updatePreKeyBundle()) {
                            is ApiResult.Success -> true
                            is ApiResult.Error -> false
                            is ApiResult.NetworkError -> false
                            is ApiResult.UnknownError -> false
                        }

                    val result = keyManagerRepository.verifyOwnServerPreKeys(
                        server = serverVerification,
                        localIdentitySigningPublicKey = localKeys.identitySigningKeyPublic,
                        localSignedPreKeyBundle = localSPK,
                        verifySignature = { publicKey, message, signature ->
                            crypto.verifySignature(
                                publicKey = publicKey,
                                message = message,
                                signature = signature
                            )
                        }
                    )

                    if(!result.isValid){
                        return  false
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


    suspend fun updateAccountInfo(
        request : UpdateUserRequest
    ): ApiResult<Unit> {
        return try {
            val user = localUser.getUser()
                ?: throw RuntimeException("Failed To retrieve local user info")
            when (val response = remoteUser.updateAccount(request)) {
                is ApiResult.Success -> {
                    localUser.updateUser(request.toUser(user))
                    ApiResult.Success(Unit)
                }

                is ApiResult.Error -> {
                    response
                }

                is ApiResult.NetworkError -> {
                    response
                }

                is ApiResult.UnknownError -> {
                    response
                }
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Failed to update account info")
        }
    }


    suspend fun logout() {
        try {
            remoteUser.logout()
        } catch (e: Exception) {
            // Log the error or handle it as needed
            println("Error during logout: ${e.message}")
        } finally {
            tokenManager.clearTokens()
        }
    }

    suspend fun searchAllUsers(): ApiResult<List<String>> {
        return try {
            when(val response = remoteUser.getAllUsers()){
                is ApiResult.Success -> {
                    val usernames = response.data.map { it.username }
                    ApiResult.Success(usernames)
                }
                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        }catch (e: Exception){
            ApiResult.UnknownError(e.message ?: "Failed to fetch users")
        }
    }

    suspend fun searchByUsername(username: String): ApiResult<String> {
        return try {
            when(val response = remoteUser.getUserByUsername(username)){
                is ApiResult.Success -> {
                    ApiResult.Success(response.data.username)
                }
                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        }catch (e: Exception){
            ApiResult.UnknownError(e.message ?: "Failed to fetch user")
        }
    }

}