package org.e2ee.data.remote.users.dto

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundleDto

data class UserRequestDto(
    var username: String,

    var email: String,

    var password: String,

    val avatarUrl: String? = null,

    var preKeyBundle: PreKeyBundleDto,
)
