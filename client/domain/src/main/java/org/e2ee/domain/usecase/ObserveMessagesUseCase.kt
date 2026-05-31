package org.e2ee.domain.usecase

import kotlinx.coroutines.flow.Flow
import org.e2ee.domain.model.Message
import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class ObserveMessagesUseCase @Inject constructor(
    private val chatRepository: ChatRepository
) {
    operator fun invoke(sessionId: String): Flow<List<Message>> {
        return chatRepository.observeMessages(sessionId)
    }
}