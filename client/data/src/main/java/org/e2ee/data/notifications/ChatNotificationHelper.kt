package org.e2ee.data.notifications

/**
 * Minimal notification helper used by ChatRepository. Keep implementation simple so it compiles.
 */
class ChatNotificationHelper {
    fun showMessageNotification(senderId: String, messageBody: String) {
        // No-op for now. In a real app this would post a platform notification.
        println("Notification from $senderId: $messageBody")
    }
}

