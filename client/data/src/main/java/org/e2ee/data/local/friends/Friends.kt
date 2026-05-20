package org.e2ee.data.local.friends

import androidx.room.Entity

@Entity(tableName = "friends", primaryKeys = ["userId"])
data class Friends(
    val userId: Long,
    val username: String,
    val email: String,
    val avatarUrl: String? = null,
)