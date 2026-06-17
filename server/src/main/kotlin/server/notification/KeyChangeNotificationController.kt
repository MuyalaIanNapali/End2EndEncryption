package server.notification

import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.simp.SimpMessagingTemplate
import org.springframework.stereotype.Controller
import java.security.Principal

@Controller
class KeyChangeNotificationController(
    private val messagingTemplate: SimpMessagingTemplate,
    private val service: KeyChangeNotificationService
) {

    @MessageMapping("/key-change")
    fun processNotification(
        principal: Principal
    ) {
        val notification = service.saveKeyChangeNotification(principal.name)

        messagingTemplate.convertAndSend(
            "/topic/key-change",
            notification
        )
    }

    @MessageMapping("/key-change/sync")
    fun processNotificationSync(){

    }
}