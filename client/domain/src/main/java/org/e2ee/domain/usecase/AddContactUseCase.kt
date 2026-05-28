package org.e2ee.domain.usecase

import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class AddContactUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(details: RemoteUserDetails) {
        userRepository.addContact(details)
    }
}