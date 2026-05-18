package server.ws

import org.springframework.messaging.Message
import org.springframework.messaging.MessageChannel
import org.springframework.messaging.simp.stomp.StompCommand
import org.springframework.messaging.simp.stomp.StompHeaderAccessor
import org.springframework.messaging.support.ChannelInterceptor
import org.springframework.messaging.support.MessageHeaderAccessor
import org.springframework.stereotype.Component
import server.jwt.JWTService

@Component
class JwtStompChannelInterceptor(
    private val jwtService: JWTService
) : ChannelInterceptor {

    override fun preSend(
        message: Message<*>,
        channel: MessageChannel
    ): Message<*> {
        val accessor = MessageHeaderAccessor.getAccessor(
            message,
            StompHeaderAccessor::class.java
        ) ?: return message

        if (accessor.command == StompCommand.CONNECT) {
            val authHeader = accessor.getFirstNativeHeader("Authorization")
                ?: throw IllegalArgumentException("Missing Authorization header")

            val token = authHeader.removePrefix("Bearer ").trim()

            val userId = jwtService.extractUserId(token)

            accessor.user = StompPrincipal(userId.toString())
        }

        return message
    }
}