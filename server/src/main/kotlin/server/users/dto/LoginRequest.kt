package server.users.dto

import jakarta.validation.constraints.NotNull

data class LoginRequest(
    @field:NotNull(message = "Email or username is required")
    var identifier: String,

    @field: NotNull(message = "Password must be provided")
    var password: String,
)
