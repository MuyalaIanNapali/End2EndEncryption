package server.users

import java.time.LocalDateTime

data class UpdateUserRequest(
    val username: String?,
    val email: String?,
    val password: String?,
    val avatarUrl: String?
)
