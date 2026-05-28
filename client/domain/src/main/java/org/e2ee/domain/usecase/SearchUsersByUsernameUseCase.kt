package org.e2ee.domain.usecase

import android.util.Log
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class SearchUsersByUsernameUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(username: String): DomainResult<List<RemoteUserDetails>> {
        Log.d("search", "Searching for users with username: $username")
        return userRepository.searchUsersByUsername(username)
    }
}