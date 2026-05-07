package server.users.dto

import java.time.LocalDateTime

data class UserResponse(
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
    val isOnline: Boolean,
    val lastSeen: LocalDateTime? = null,
)
