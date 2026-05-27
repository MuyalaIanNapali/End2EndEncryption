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
            Log.d("CreateAccountDebug", "getting user keys")
            var userKeys = keysRepository.getUserKeys()


            Log.d("CreateAccountDebug", "getting user keys 2")
            if (userKeys == null) {
                Log.d("CreateAccountDebug", "generating user keys")
                keysRepository.generateAndStoreUserKeys()
                Log.d("CreateAccountDebug", "userkeys generated")
                userKeys = keysRepository.getUserKeys()
                    ?: return ApiResult.UnknownError("Failed to generate user keys")
            }

            Log.d("CreateAccountDebug", "getting spk")

            var signedPreKey = spkRepository.getActiveSignedPreKeyBundle()

            if (signedPreKey == null) {
                spkRepository.rotateIfExpired()
                signedPreKey = spkRepository.getActiveSignedPreKeyBundle()
                    ?: return ApiResult.UnknownError("Failed to generate signed pre-key")
            }

            Log.d("CreateAccountDebug", "getting opks")
            var opks = opkRepository.getNotUploaded()

            if (opks.isNullOrEmpty()) {
                opkRepository.generateAndStoreOPK(100)
                opks = opkRepository.getNotUploaded()
            }

            if (opks.isNullOrEmpty()) {
                return ApiResult.UnknownError("Failed to generate one-time pre-keys")
            }

            Log.d("CreateAccountDebug", "Create prekey bundle")
            val preKeyBundle = PreKeyBundleDto(
                userId = null,
                identityKey = userKeys.identityKeyPublic,
                identityKeySigning = userKeys.identitySigningKeyPublic,
                signedPreKeyBundle = signedPreKey,
                opkMap = opks.associate { it.opkId to it.publicKey }
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