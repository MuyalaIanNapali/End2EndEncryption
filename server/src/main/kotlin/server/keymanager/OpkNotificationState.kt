package server.keymanager

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDateTime

@Entity
@Table(name = "opk_notification_state")
data class OpkNotificationState(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", nullable = false)
    val userId: Long,

    @Column(name= "last_notified_at")
    var lastNotifiedAt: LocalDateTime? = null,

    @Column(name= "notification_sent")
    var notificationSent: Boolean = false
)


