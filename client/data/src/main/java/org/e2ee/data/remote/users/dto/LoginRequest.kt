package org.e2ee.data.remote.users.dto


data class LoginRequest(
    var identifier: String,

    var password: String,
)
