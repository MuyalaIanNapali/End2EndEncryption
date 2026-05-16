package org.e2ee.data.userKeys

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "user_keys")
data class UserKeys(
    @PrimaryKey
    val id: Int = 1,

    val userId : Long ? = null,
    val identityKeyPub: ByteArray,
    val identityKeyPriv : ByteArray,
    val identitySigningKeyPub : ByteArray,
    val identitySigningKeyPriv : ByteArray
)