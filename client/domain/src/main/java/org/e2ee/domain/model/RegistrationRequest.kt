package org.e2ee.domain.model

data class RegistrationRequest(
    val username: String,
    val email: String,
    val password: String,
    val avatarUrl: String? = null
)
