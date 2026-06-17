package server.notification

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDateTime

@Entity
@Table(name = "keyNotification")
class KeyChangeNotification(
    @Id
    val id: String,

    @Column(name = "userId", nullable = false)
    val userId: Long,

    @Column(name = "createdAt", nullable = false )
    val createdAt: LocalDateTime
)