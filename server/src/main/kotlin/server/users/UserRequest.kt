package server.users

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotNull

data class UserRequest(
    @field:NotNull(message = "Username must be provided")
    var username: String,

    @field:NotNull(message = "Email must be provided")
    @field:Email(message = "Email must be valid")
    var email: String,

    @field:NotNull(message = "Password must be provided")
    var password: String,

    val avatarUrl: String? = null,
)
