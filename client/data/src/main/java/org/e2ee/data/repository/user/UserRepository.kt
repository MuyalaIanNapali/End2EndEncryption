package org.e2ee.data.repository.user

import org.e2ee.data.repository.mapper.toDomainResult
import org.e2ee.data.repository.mapper.toLoginRequestDto
import org.e2ee.data.repository.mapper.toUpdateUserRequest
import org.e2ee.data.repository.mapper.toUserRequest
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.LoginRequest
import org.e2ee.domain.model.RegistrationRequest
import org.e2ee.domain.model.UpdateAccountInfoRequest
import org.e2ee.domain.repository.AuthRepository
import org.e2ee.domain.repository.UserRepository as UserRepositoryContract
import javax.inject.Inject

class UserRepository @Inject constructor(
    private val userRegistrationRepository: UserRegistrationRepository,
    private val userLoginRepository: UserLoginRepository,
    private val userAccountRepository: UserAccountRepository,
    private val userLogoutRepository: UserLogoutRepository,
    private val userSearchRepository: UserSearchRepository
): AuthRepository, UserRepositoryContract{

    override suspend fun register(request: RegistrationRequest): DomainResult<Boolean> {
        return userRegistrationRepository
            .register(request.toUserRequest())
            .toDomainResult()
    }

    override suspend fun login(request: LoginRequest): DomainResult<Boolean> {
        return userLoginRepository.login(request.toLoginRequestDto())
    }

    override suspend fun updateAccountInfo(
        request: UpdateAccountInfoRequest
    ): DomainResult<Unit> {
        return userAccountRepository
            .updateAccountInfo(request.toUpdateUserRequest())
            .toDomainResult()
    }

     override suspend fun logout() {
        userLogoutRepository.logout()
    }

    override suspend fun searchAllUsers(): DomainResult<List<String>> {
        return userSearchRepository
            .searchAllUsers()
            .toDomainResult()
    }

    override suspend fun searchByUsername(username: String): DomainResult<String> {
        return userSearchRepository
            .searchByUsername(username)
            .toDomainResult()
    }
}