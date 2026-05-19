package server.users

import jakarta.transaction.Transactional
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import server.exceptionHandler.EmailAlreadyTakenException
import server.exceptionHandler.InvalidCredentialsException
import server.exceptionHandler.UserNotFoundException
import server.exceptionHandler.UsernameAlreadyTakenException
import server.jwt.JWTService
import server.jwt.RefreshRequest
import server.jwt.RefreshResponse
import server.jwt.RefreshTokenService
import server.keymanager.KeyManagerService
import server.users.dto.LoginRequest
import server.users.dto.LoginResponse
import server.users.dto.UpdateUserRequest
import server.users.dto.UserRequest
import server.users.dto.UserResponse
import java.time.LocalDateTime

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val refreshTokenService: RefreshTokenService,
    private val jwtService: JWTService,
    private val keyManagerService: KeyManagerService,
) {

    fun hashPassword(password: String): String {
        return passwordEncoder.encode(password)!!
    }

    fun verifyPassword(
        password: String,
        hashedPassword: String
    ): Boolean {
        return passwordEncoder.matches(password, hashedPassword)
    }

    fun getUsers()= ResponseEntity.ok(
        userRepository.findAll()
            .map {
                it.toResponse(
                    LocalDateTime.now()
                )
            }
    )

    @Transactional
    fun createUser(request: UserRequest): ResponseEntity<LoginResponse> {
        val user = request.toEntity()

        if (userRepository.findByUsername(user.username) != null)
            throw UsernameAlreadyTakenException()


        // hash password
        val rawPassword = user.password
        user.password = hashPassword(rawPassword)

        userRepository.save(user)
        request.preKeyBundle.userId = user.id

        keyManagerService.savePreKeyBundle(request.preKeyBundle)

        return loginUser(LoginRequest(user.username, rawPassword))
    }

    fun loginUser(request: LoginRequest): ResponseEntity<LoginResponse> {

        val user = if (request.identifier.contains("@")) {
            userRepository.findByEmail(request.identifier)
        } else {
            userRepository.findByUsername(request.identifier)
        } ?: throw UserNotFoundException()

        if (!verifyPassword(request.password, user.password)) {
            throw InvalidCredentialsException()
        }

        val accessToken = jwtService.generateAccessToken(
            user.id!!,
            user.username,
        )
        val refreshToken = refreshTokenService.createRefreshToken(user.id!!)

        val preKeyVerification = keyManagerService.getPreKeyVerificationBundle(user.id!!)

        return ResponseEntity.ok(
            LoginResponse(
                accessToken = accessToken,
                refreshToken = refreshToken.token,
                user = user.toResponse(LocalDateTime.now()),
                preKeyVerification = preKeyVerification
            )
        )
    }

    fun findUserByUsername(
        username: String
    ): ResponseEntity<UserResponse> {
        val user = userRepository.findByUsername(username)
            ?: throw UserNotFoundException()

        return ResponseEntity.ok(user.toResponse(LocalDateTime.now()))
    }

    fun logoutUser(username: String){
        val user = userRepository.findByUsername(username)
        refreshTokenService.deleteByUser(requireNotNull(user?.id))
    }

    fun refreshToken(token: String): ResponseEntity<RefreshResponse> {
        val refresh = refreshTokenService.validate(token)


        val user = userRepository.findById(refresh.userId).orElse(null)
            ?: throw UserNotFoundException()

        refreshTokenService.deleteToken(token)

        val newAccessToken = jwtService.generateAccessToken(
            userId = user.id!!,
            requireNotNull(user.username))

        val newRefreshToken = refreshTokenService.createRefreshToken(refresh.userId)

        return ResponseEntity.ok(
            RefreshResponse(
                accessToken = newAccessToken,
                refreshToken = newRefreshToken.token
            )
        )
    }

    fun updateUserDetails(username: String, request: UpdateUserRequest) {
        val user = userRepository.findByUsername(username)
            ?: throw UserNotFoundException()

        val newUsername = request.username?.trim()
        val newEmail = request.email?.trim()?.lowercase()

        newUsername?.let {
            if (it != user.username && userRepository.findByUsername(it) != null) {
                throw UsernameAlreadyTakenException()
            }
        }

        newEmail?.let {
            if (it != user.email && userRepository.findByEmail(it) != null) {
                throw EmailAlreadyTakenException()
            }
        }

        user.updateFrom(request)

        request.password?.let { rawPassword ->
            user.password = hashPassword(rawPassword)
        }

        userRepository.save(user)
    }

}