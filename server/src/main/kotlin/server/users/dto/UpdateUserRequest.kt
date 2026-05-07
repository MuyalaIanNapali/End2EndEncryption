package server.users.dto

data class UpdateUserRequest(
    val username: String?,
    val email: String?,
    val password: String?,
    val avatarUrl: String?
)
