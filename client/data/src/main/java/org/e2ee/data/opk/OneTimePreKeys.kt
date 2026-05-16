package org.e2ee.data.opk

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "one_time_pre_keys")
data class OneTimePreKeys(
    @PrimaryKey
    val opkId: String,
    val publicKey: ByteArray,
    val privateKey: ByteArray,

    val uploaded: Boolean = false,
    val consumed: Boolean = false
)