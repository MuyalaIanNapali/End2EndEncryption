package server.chat

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(name = "pending_messages")
class PendingMessage(

    @Id
    var id: String,

    @Column(name = "sender_id", nullable = false)
    var senderId: String,

    @Column(name = "receiver_id", nullable = false)
    var receiverId: String,

    @Lob
    @Column(name = "payload_json", nullable = false, columnDefinition = "TEXT")
    var payloadJson: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    var status: MessageStatus = MessageStatus.SENT,

    @Column(name = "created_at", nullable = false)
    var createdAt: LocalDateTime = LocalDateTime.now(),

    @Column(name = "delivered_at")
    var deliveredAt: LocalDateTime? = null
)