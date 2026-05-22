package org.e2ee.domain.usecase

import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class ConnectWebSocketUseCase @Inject constructor(
    private val chatRepository: ChatRepository
) {
    operator fun invoke() {
        chatRepository.connect()
    }
}