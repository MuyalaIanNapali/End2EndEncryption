package server.users.dto

import server.keymanager.dto.PreKeyVerification

data class LoginResponse(
    val accessToken: String,
    val refreshToken: String,
    val user: UserResponse,
    val preKeyVerification: PreKeyVerification? = null
)
