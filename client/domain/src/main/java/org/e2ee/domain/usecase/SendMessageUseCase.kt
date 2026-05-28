package org.e2ee.domain.usecase

import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.repository.ChatRepository
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class SendMessageUseCase @Inject constructor(
    private val chatRepository: ChatRepository,
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(
        details: RemoteUserDetails,
        content: String
    ) {
        userRepository.addContact(details)

        chatRepository.sendMessage(details.id.toString(), content)
    }
}