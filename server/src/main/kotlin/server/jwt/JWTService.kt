package server.jwt

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.util.Date

@Service
class JWTService {

    private val secret = Keys.hmacShaKeyFor(
        "my-super-secret-key-my-super-secret-key".toByteArray()
    )

    private val accessExpiration = 1000L * 60 * 15 // 15 min

    fun generateAccessToken(userId: Long, username: String): String {
        return Jwts.builder()
            .subject(username)
            .claim("userId", userId)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + accessExpiration))
            .signWith(secret)
            .compact()
    }

    fun isTokenValid(token: String, username: String): Boolean {
        return try {
            val claims = Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .payload

            val tokenUsername = claims.subject
            val expiration = claims.expiration

            tokenUsername == username && expiration.after(Date())
        } catch (e: Exception) {
            false
        }
    }

    fun extractUsername(token: String): String? {
        return try {
            Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .payload
                .subject
        } catch (e: Exception) {
            null
        }
    }

    fun extractUserId(token: String): Long? {
        return try {
            val claims = Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .payload

            when (val userId = claims["userId"]) {
                is Int -> userId.toLong()
                is Long -> userId
                is Number -> userId.toLong()
                is String -> userId.toLong()
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }
}