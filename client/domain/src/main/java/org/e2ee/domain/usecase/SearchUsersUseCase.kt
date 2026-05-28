package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class SearchUsersUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(): DomainResult<List<RemoteUserDetails>> {
        return userRepository.searchAllUsers()
    }

    suspend operator fun invoke(username: String): DomainResult<RemoteUserDetails> {
        return userRepository.searchByUsername(username)
    }
}