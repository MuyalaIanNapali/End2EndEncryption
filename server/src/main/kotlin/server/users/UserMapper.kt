package server.users

import server.users.dto.LoginResponse
import server.users.dto.UpdateUserRequest
import server.users.dto.UserRequest
import server.users.dto.UserResponse
import java.time.LocalDateTime

// Entity → Response
fun User.toResponse(now: LocalDateTime) = UserResponse(
    username = username,
    email = email,
    avatarUrl = avatarUrl,
    isOnline = isOnline(now),
    lastSeen = lastSeen
)

// Request → Entity
fun UserRequest.toEntity() = User(
    username = username,
    email = email,
    password = password,
    avatarUrl = avatarUrl
)

// Update existing entity
fun User.updateFrom(request: UpdateUserRequest) {
    request.username?.let { username = it }
    request.email?.let { email = it }
    request.password?.let { password = it }
    request.avatarUrl?.let { avatarUrl = it }
}
