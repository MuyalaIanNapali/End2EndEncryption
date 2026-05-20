package org.e2ee.data.local.user

import androidx.room.Entity
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest

@Entity(tableName = "user")
data class User(
    val localId: Long = 1L, // Always 1 since we only store one user locally
    val userId: Long,
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
)

fun UpdateUserRequest.toUser(existingUser: User): User {
    return User(
        localId = existingUser.localId,
        userId = existingUser.userId,
        username = this.username ?: existingUser.username,
        email = this.email ?: existingUser.email,
        avatarUrl = this.avatarUrl ?: existingUser.avatarUrl
    )
}