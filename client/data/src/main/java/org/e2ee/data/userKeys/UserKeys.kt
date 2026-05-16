package org.e2ee.data.userKeys

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "user_keys")
data class UserKeys(
    @PrimaryKey
    val id: Int = 1,

    val userId : Long ? = null,
    val identityKeyPub: ByteArray,
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
        if (!identityKeyPub.contentEquals(other.identityKeyPub)) return false
        if (!identityKeyPrivate.contentEquals(other.identityKeyPrivate)) return false
        if (!identitySigningKeyPublic.contentEquals(other.identitySigningKeyPublic)) return false
        if (!identitySigningKeyPrivate.contentEquals(other.identitySigningKeyPrivate)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id
        result = 31 * result + (userId?.hashCode() ?: 0)
        result = 31 * result + identityKeyPub.contentHashCode()
        result = 31 * result + identityKeyPrivate.contentHashCode()
        result = 31 * result + identitySigningKeyPublic.contentHashCode()
        result = 31 * result + identitySigningKeyPrivate.contentHashCode()
        return result
    }
}