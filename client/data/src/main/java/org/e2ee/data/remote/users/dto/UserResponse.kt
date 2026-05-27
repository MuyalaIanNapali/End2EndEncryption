package org.e2ee.data.remote.users.dto

import org.e2ee.data.local.user.User
import java.time.LocalDateTime

data class UserResponse(
    val id: Long,
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
    val isOnline: Boolean,
    val lastSeen: String ?= null
) {
    fun toUser(): User {
        return User(
            userId = id,
            username = username,
            email = email,
            avatarUrl = avatarUrl
        )
    }
}
