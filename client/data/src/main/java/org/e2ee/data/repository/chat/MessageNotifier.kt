package org.e2ee.data.repository.chat

interface MessageNotifier {
    fun showMessageNotification(
        senderId: String,
        message: String
    )
}