package server.jwt

import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.util.UUID

@Service
class RefreshTokenService(
    private val repo: RefreshTokenRepository
) {

    private val refreshExpirationDays = 7L

    fun createRefreshToken(userid: Long): RefreshToken {
        val token = UUID.randomUUID().toString()

        val refreshToken = RefreshToken(
            token = token,
            userId = userid,
            expiresAt = LocalDateTime.now().plusDays(refreshExpirationDays)
        )

        return repo.save(refreshToken)
    }

    fun validate(token: String): RefreshToken {
        val refreshToken = repo.findByToken(token)
            ?: throw RuntimeException("Invalid refresh token")

        if (refreshToken.expiresAt.isBefore(LocalDateTime.now())) {
            throw RuntimeException("Refresh token expired")
        }

        return refreshToken
    }

    fun deleteByUser(userId: Long) {
        repo.deleteByUserId(userId)
    }

    fun deleteToken(token: String) {
        val refreshToken = repo.findByToken(token)
            ?: throw RuntimeException("Invalid refresh token")

        repo.delete(refreshToken)
    }
}