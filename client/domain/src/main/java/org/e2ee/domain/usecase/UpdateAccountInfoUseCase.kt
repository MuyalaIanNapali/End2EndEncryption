package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.UpdateAccountInfoRequest
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class UpdateAccountInfoUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(
        request: UpdateAccountInfoRequest
    ): DomainResult<Unit> {
        return userRepository.updateAccountInfo(request)
    }
}