package server.notification

import org.springframework.data.jpa.repository.JpaRepository

interface KeyChangeNotificationRepository: JpaRepository<KeyChangeNotification, Long> {
}