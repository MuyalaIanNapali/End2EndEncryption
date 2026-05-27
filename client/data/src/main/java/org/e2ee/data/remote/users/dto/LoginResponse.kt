package org.e2ee.data.remote.users.dto

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerification

data class LoginResponse(
    val accessToken: String,
    val refreshToken: String,
    val user: UserResponse,
    val preKeyVerification: PreKeyVerification
)
