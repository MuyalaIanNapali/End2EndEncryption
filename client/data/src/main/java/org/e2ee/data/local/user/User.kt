package org.e2ee.data.local.user

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.data.remote.users.dto.UserRequest

@Entity(tableName = "user", indices = [Index(value = ["userId"], unique = true)])
data class User(
    @PrimaryKey
    val localId: Long = 1L, // Always 1 since we only store one user locally
    val userId: Long,
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
    val isLoggedIn: Boolean = true
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