package server.notification

import java.time.LocalDateTime

data class KeyChangeNotificationResponse(
    val id: String,
    val userId: Long,
    val username: String,
    val createdAt: LocalDateTime
)