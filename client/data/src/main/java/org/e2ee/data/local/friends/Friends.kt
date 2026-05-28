package org.e2ee.data.local.friends

import androidx.room.Entity
import org.e2ee.domain.model.RemoteUserDetails

@Entity(tableName = "friends", primaryKeys = ["userId"])
data class Friends(
    val userId: Long,
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
)

fun RemoteUserDetails.toFriends(): Friends {
    return Friends(
        userId = this.id,
        username = this.username,
        email = this.email,
        avatarUrl = null // Assuming avatarUrl is not available in RemoteUserDetails
    )
}