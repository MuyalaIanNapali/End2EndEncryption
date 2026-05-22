package org.e2ee.data.repository.mapper

import org.e2ee.data.remote.users.dto.LoginRequestDto
import org.e2ee.data.remote.users.dto.UpdateUserRequest
import org.e2ee.domain.model.UpdateAccountInfoRequest
import org.e2ee.domain.model.LoginRequest
import org.e2ee.domain.model.RegistrationRequest

fun RegistrationRequest.toUserRequest() = org.e2ee.data.remote.users.dto.UserRequest(
    username = this.username,
    email = this.email,
    password = this.password,
    avatarUrl = this.avatarUrl
)

fun LoginRequest.toLoginRequestDto() = LoginRequestDto(
    identifier = this.identifier,
    password = this.password
)

fun UpdateAccountInfoRequest.toUpdateUserRequest() = UpdateUserRequest(
    username = this.username,
    email = this.email,
    password = this.password,
    avatarUrl = this.avatarUrl
)