package org.e2ee.domain.usecase

import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class MarkChatsAsReadUseCase @Inject constructor(
    private val chatRepository: ChatRepository
) {
    suspend operator fun invoke(sessionId: String) {
        chatRepository.markMessagesAsRead(sessionId)
    }
}