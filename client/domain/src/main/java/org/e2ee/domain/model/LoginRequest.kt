package org.e2ee.domain.model

data class LoginRequest(
    val identifier : String, // Can be either username or email
    val password: String
)
