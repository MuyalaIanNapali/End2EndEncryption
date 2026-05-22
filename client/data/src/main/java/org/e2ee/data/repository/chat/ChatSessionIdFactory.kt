package org.e2ee.data.repository.chat

import javax.inject.Inject

class ChatSessionIdFactory @Inject constructor() {

    fun createSessionId(
        localUserId: String,
        otherUserId: String
    ): String {
        return "${localUserId}_${otherUserId}"
    }
}