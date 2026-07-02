package org.e2ee.domain.usecase

import kotlinx.coroutines.flow.StateFlow
import org.e2ee.domain.model.ConnectionState
import org.e2ee.domain.repository.ChatRepository
import javax.inject.Inject

class ObserveWebSocketConnectionUseCase @Inject constructor(
    private val repository: ChatRepository
) {
    operator fun invoke(): StateFlow<ConnectionState> {
        return repository.connectionState
    }
}