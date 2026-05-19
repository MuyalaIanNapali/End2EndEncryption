package org.e2ee.data.local.user

import androidx.room.Entity

@Entity(tableName = "user")
data class User(
    val localId: Long = 1L, // Always 1 since we only store one user locally
    val id: Long? = null, // Server-assigned ID, null until registered
    val username: String,
    val email: String,
    val password: String,
    val avatarUrl: String? = null,
)