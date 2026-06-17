package server.notification

import org.springframework.stereotype.Service
import server.exceptionHandler.UserNotFoundException
import server.users.UserRepository
import java.time.LocalDateTime
import java.util.UUID

@Service
class KeyChangeNotificationService(
    private val repository: KeyChangeNotificationRepository,
    private val userRepository: UserRepository
) {

    fun saveKeyChangeNotification(username: String): KeyChangeNotificationResponse {
        val user = userRepository.findByUsername(username)
            ?: throw UserNotFoundException("User not found: $username")

        val notification = KeyChangeNotification(
            id = UUID.randomUUID().toString(),
            userId = user.id!!,
            createdAt = LocalDateTime.now()
        )

        val savedNotification = repository.save(notification)

        return KeyChangeNotificationResponse(
            id = savedNotification.id,
            userId = savedNotification.userId,
            username = username,
            createdAt = savedNotification.createdAt
        )
    }
}