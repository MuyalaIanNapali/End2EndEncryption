package server.chat

import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component
import org.springframework.web.socket.messaging.SessionConnectedEvent
import org.springframework.web.socket.messaging.SessionDisconnectEvent
import java.util.concurrent.ConcurrentHashMap

@Component
class OnlineUserTracker(
    private val chatService: ChatService,
    private val messagingTemplate: org.springframework.messaging.simp.SimpMessagingTemplate
) {

    private val onlineUsers = ConcurrentHashMap.newKeySet<String>()

    fun isOnline(userId: String): Boolean {
        return onlineUsers.contains(userId)
    }

    @EventListener
    fun handleConnected(event: SessionConnectedEvent) {
        val userId = event.user?.name ?: return

        onlineUsers.add(userId)

        val pendingMessages = chatService.getPendingMessagesFor(userId)

        pendingMessages.forEach { message ->
            messagingTemplate.convertAndSendToUser(
                userId,
                "/queue/messages",
                message
            )
        }
    }

    @EventListener
    fun handleDisconnected(event: SessionDisconnectEvent) {
        val userId = event.user?.name ?: return
        onlineUsers.remove(userId)
    }
}