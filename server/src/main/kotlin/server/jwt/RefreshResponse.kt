package server.jwt

data class RefreshResponse(
    val refreshToken: String,
    val accessToken: String
)
