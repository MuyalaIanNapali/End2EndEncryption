package org.e2ee.domain.notifications

interface MessageNotifier {
    fun showMessageNotification(
        senderId: String,
        messageBody: String
    )
}