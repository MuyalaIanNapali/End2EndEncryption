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

    private val accessExpiration = 1000 * 60 * 15 // 15 min

    fun generateAccessToken(userId: Long): String {
        return Jwts.builder()
            .subject(userId.toString())
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + accessExpiration))
            .signWith(secret)
            .compact()
    }

    fun extractUsername(token: String): String {
        return Jwts.parser()
            .verifyWith(secret)
            .build()
            .parseSignedClaims(token)
            .payload
            .subject
    }

    fun isValid(token: String): Boolean {
        return try {
            val claims = Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)

            claims.payload.expiration.after(Date())
        } catch (e: Exception) {
            false
        }
    }
}