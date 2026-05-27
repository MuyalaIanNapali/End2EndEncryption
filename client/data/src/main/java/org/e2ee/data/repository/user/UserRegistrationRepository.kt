package org.e2ee.data.repository.user

import android.util.Log
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.users.dto.UserRequest
import org.e2ee.data.remote.users.dto.UserRequestDto
import javax.inject.Inject

class UserRegistrationRepository @Inject constructor(
    private val remoteUser: RemoteUserRepository,
    private val localUser: LocalUserRepository,
    private val tokenManager: TokenManager,
    private val keysRepository: UserKeysRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository
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

            var opks = opkRepository.getNotUploaded()

            if (opks.isNullOrEmpty()) {
                opkRepository.generateAndStoreOPK(100)
                opks = opkRepository.getNotUploaded()
            }

            if (opks.isNullOrEmpty()) {
                return ApiResult.UnknownError("Failed to generate one-time pre-keys")
            }


            val preKeyBundle = PreKeyBundleDto(
                userId = null,
                identityKey = userKeys.identityKeyPublic,
                identityKeySigning = userKeys.identitySigningKeyPublic,
                signedPreKeyBundle = signedPreKey,
                opkMap = opks.associate { it.opkId to it.publicKey }
            )

            val registrationRequest = UserRequestDto(
                username = request.username,
                email = request.email,
                password = request.password,
                avatarUrl = request.avatarUrl,
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
                        opks.map { it.opkId }
                    )

                    ApiResult.Success(true)
                }

                is ApiResult.Error -> response
                is ApiResult.NetworkError -> response
                is ApiResult.UnknownError -> response
            }
        } catch (e: Exception) {
            ApiResult.UnknownError(e.message ?: "Registration failed")
        }
    }
}