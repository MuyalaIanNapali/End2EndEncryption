package org.e2ee.domain.usecase

import org.e2ee.domain.model.ChatRoomDomain
import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class GetChatRoomUseCase @Inject constructor(
    private val chatRepository: ChatRepository
) {
    suspend operator fun invoke(receiverId: String): ChatRoomDomain? {
        return chatRepository.getChatRoomByReceiverId(receiverId)
    }
}