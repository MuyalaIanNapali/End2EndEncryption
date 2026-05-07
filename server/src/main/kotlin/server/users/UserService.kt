package server.users

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import server.jwt.JWTService
import server.jwt.RefreshResponse
import server.jwt.RefreshTokenService
import server.users.dto.LoginRequest
import server.users.dto.LoginResponse
import server.users.dto.UserRequest
import server.users.dto.UserResponse
import java.time.LocalDateTime

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val refreshTokenService: RefreshTokenService,
    private val jwtService: JWTService
) {

    fun hashPassword(password: String): String {
        return passwordEncoder.encode(password)!!
    }

    fun verifyPassword(password: String, hashedPassword: String): Boolean {
        return passwordEncoder.matches(password, hashedPassword)
    }

    fun getUsers() = ResponseEntity.ok(userRepository.findAll())

    fun createUser(request: UserRequest): ResponseEntity<UserResponse> {
        val user = request.toEntity()

        // hash password
        user.password = hashPassword(user.password)

        userRepository.save(user)

        return ResponseEntity.ok(user.toResponse(LocalDateTime.now()))
    }

    fun loginUser(request: LoginRequest): ResponseEntity<Any> {

        val user = if (request.identifier.contains("@")) {
            userRepository.findByEmail(request.identifier)
        } else {
            userRepository.findByUsername(request.identifier)
        } ?: return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body("User not found")

        if (!verifyPassword(request.password, user.password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid password")
        }

        val accessToken = jwtService.generateAccessToken(requireNotNull(user.id))
        val refreshToken = refreshTokenService.createRefreshToken(requireNotNull(user.id))

        return ResponseEntity.ok(
            LoginResponse(
                accessToken = accessToken,
                refreshToken = refreshToken.token,
                user = user.toResponse(LocalDateTime.now())
            )
        )
    }

    fun findUserByUsername(username: String): ResponseEntity<UserResponse> {
        val user = userRepository.findByUsername(username)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).build()

        return ResponseEntity.ok(user.toResponse(LocalDateTime.now()))
    }

    fun logoutUser(username: String): ResponseEntity<Void> {
        val user = userRepository.findByUsername(username)
        refreshTokenService.deleteByUser(requireNotNull(user?.id))
        return ResponseEntity.noContent().build()
    }

    fun refreshToken(token: String): ResponseEntity<RefreshResponse> {
        val refresh = refreshTokenService.validate(token)

        refreshTokenService.deleteToken(token)

        val newAccessToken = jwtService.generateAccessToken(refresh.userId)

        val newRefreshToken = refreshTokenService.createRefreshToken(refresh.userId)

        return ResponseEntity.ok(
            RefreshResponse(
                accessToken = newAccessToken,
                refreshToken = newRefreshToken.token
            )
        )
    }

}