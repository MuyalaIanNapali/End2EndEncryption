package org.e2ee.domain.usecase

import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class SendMessageUseCase @Inject constructor(
    private val chatRepository: ChatRepository
) {
    suspend operator fun invoke(
        receiverId: String,
        content: String
    ) {
        chatRepository.sendMessage(receiverId, content)
    }
}