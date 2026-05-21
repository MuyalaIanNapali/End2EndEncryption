package org.e2ee.data.repository.chat

class ChatSessionIdFactory {

    fun createSessionId(
        localUserId: String,
        otherUserId: String
    ): String {
        return "${localUserId}_${otherUserId}"
    }
}