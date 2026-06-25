package org.e2ee.data.local.friends

import androidx.room.Entity
import kotlinx.serialization.Serializable
import org.e2ee.domain.model.RemoteUserDetails

@Serializable
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