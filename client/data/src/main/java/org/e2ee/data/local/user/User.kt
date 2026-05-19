package org.e2ee.data.local.user

import androidx.room.Entity
import org.e2ee.data.remote.users.dto.UserRequest

@Entity(tableName = "user")
data class User(
    val localId: Long = 1L, // Always 1 since we only store one user locally
    val userId: Long? = null, // Server-assigned ID, null until registered
    val username: String,
    val email: String,
    val password: String,
    val avatarUrl: String? = null,
)

fun UserRequest.toUser(): User {
    return User(
        username = this.username,
        email = this.email,
        password = this.password,
        avatarUrl = this.avatarUrl
    )
}