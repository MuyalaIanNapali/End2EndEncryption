package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class SearchUsersUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(): List<String> {
        return when (val result = userRepository.searchAllUsers()) {
            is DomainResult.Success -> result.data
            is DomainResult.Error -> emptyList()
            DomainResult.NetworkError -> emptyList()
            is DomainResult.UnknownError -> emptyList()
        }
    }

    suspend operator fun invoke(username: String): String? {
        return when (val result = userRepository.searchByUsername(username)) {
            is DomainResult.Success -> result.data
            is DomainResult.Error -> null
            DomainResult.NetworkError -> "Network error"
            is DomainResult.UnknownError -> "Unknown error Try again later"
        }
    }
}