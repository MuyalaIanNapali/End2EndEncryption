package org.e2ee.data.remote.users.dto


data class LoginRequestDto(
    var identifier: String,

    var password: String,
)
