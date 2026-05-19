package org.e2ee.data.remote.users.dto

data class UpdateUserRequest(
    val username: String?,
    val email: String?,
    val password: String?,
    val avatarUrl: String?
)
