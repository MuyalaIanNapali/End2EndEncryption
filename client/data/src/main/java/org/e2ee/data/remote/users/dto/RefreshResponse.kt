package org.e2ee.data.remote.users.dto

data class RefreshResponse(
    val refreshToken: String,
    val accessToken: String
)
