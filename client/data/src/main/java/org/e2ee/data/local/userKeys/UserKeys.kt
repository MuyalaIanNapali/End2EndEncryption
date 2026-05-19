package org.e2ee.data.local.userKeys

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "user_keys")
data class UserKeys(
    @PrimaryKey
    val id: Int = 1,

    val userId : Long ? = null,
    val identityKeyPublic: ByteArray,
    val identityKeyPrivate : ByteArray,
    val identitySigningKeyPublic : ByteArray,
    val identitySigningKeyPrivate : ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as UserKeys

        if (id != other.id) return false
        if (userId != other.userId) return false
        if (!identityKeyPublic.contentEquals(other.identityKeyPublic)) return false
        if (!identityKeyPrivate.contentEquals(other.identityKeyPrivate)) return false
        if (!identitySigningKeyPublic.contentEquals(other.identitySigningKeyPublic)) return false
        if (!identitySigningKeyPrivate.contentEquals(other.identitySigningKeyPrivate)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id
        result = 31 * result + (userId?.hashCode() ?: 0)
        result = 31 * result + identityKeyPublic.contentHashCode()
        result = 31 * result + identityKeyPrivate.contentHashCode()
        result = 31 * result + identitySigningKeyPublic.contentHashCode()
        result = 31 * result + identitySigningKeyPrivate.contentHashCode()
        return result
    }
}