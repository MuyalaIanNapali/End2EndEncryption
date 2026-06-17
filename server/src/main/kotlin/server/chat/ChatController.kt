package server.chat

import org.springframework.kafka.core.KafkaTemplate
import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.handler.annotation.Payload
import org.springframework.messaging.simp.SimpMessagingTemplate
import org.springframework.stereotype.Controller
import java.security.Principal

@Controller
class ChatController(
    private val messagingTemplate: SimpMessagingTemplate,
    private val chatService: ChatService,
    private val onlineUserTracker: OnlineUserTracker,
    private val kafkaTemplate: KafkaTemplate<String, ChatMessage>
) {

    @MessageMapping("/chat")
    fun processMessage(
        @Payload request: ChatRequest,
        principal: Principal
    ) {
        val senderId = principal.name

        if (senderId != request.senderId) {
            throw IllegalArgumentException("Sender ID does not match authenticated user")
        }

        val chatMessage = chatService.createPendingMessage(request)

        messagingTemplate.convertAndSendToUser(
            request.senderId,
            "/queue/message-status",
            MessageAck(chatMessage.messageId, MessageStatus.SENT)
        )

        if (onlineUserTracker.isOnline(request.receiverId)) {
            messagingTemplate.convertAndSendToUser(
                request.receiverId,
                "/queue/messages",
                chatMessage
            )
        } else {
            kafkaTemplate.send("offline-chat-messages", request.receiverId, chatMessage)
        }
    }

    @MessageMapping("/chat/delivered")
    fun markDelivered(
        @Payload request: DeliveryReceiptRequest,
        principal: Principal
    ) {
        val receiverId = principal.name

        if (receiverId != request.receiverId) {
            throw IllegalArgumentException("Receiver ID does not match authenticated user")
        }

        chatService.markDelivered(request.messageId)

        messagingTemplate.convertAndSendToUser(
            request.senderId,
            "/queue/message-status",
            MessageAck(
                messageId = request.messageId,
                status = MessageStatus.DELIVERED
            )
        )
    }

    @MessageMapping("/chat/sync")
    fun syncPendingMessages(principal: Principal) {
        val receiverId = principal.name

        val pendingMessages = chatService.getPendingMessagesFor(receiverId)

        pendingMessages.forEach { message ->
            messagingTemplate.convertAndSendToUser(
                receiverId,
                "/queue/messages",
                message
            )
        }
    }
}