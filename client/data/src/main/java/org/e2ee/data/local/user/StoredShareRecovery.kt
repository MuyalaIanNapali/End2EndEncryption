package org.e2ee.data.local.user

import kotlinx.serialization.Serializable
import org.e2ee.common.Share

@Serializable
data class StoredRecoveryShare(
    val version: Int = 1,
    val share: Share
)