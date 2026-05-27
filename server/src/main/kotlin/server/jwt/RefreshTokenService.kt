package server.jwt

import org.springframework.stereotype.Service
import server.exceptionHandler.InvalidRefreshTokenException
import server.exceptionHandler.TokenExpiredException
import java.time.LocalDateTime
import java.util.UUID

@Service
class RefreshTokenService(
    private val repo: RefreshTokenRepository
) {

    private val refreshExpirationDays = 7L

    fun createRefreshToken(userId : Long): RefreshToken {
        val token = UUID.randomUUID().toString()

        val refreshToken = RefreshToken(
            token = token,
            userId = userId,
            expiresAt = LocalDateTime.now().plusDays(refreshExpirationDays)
        )

        return repo.save(refreshToken)
    }

    fun validate(token: String): RefreshToken {
        val refreshToken = repo.findByToken(token)
            ?: throw InvalidRefreshTokenException()

        if (refreshToken.expiresAt.isBefore(LocalDateTime.now())) {
            throw TokenExpiredException()
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