package org.e2ee.data.signedPreKeys

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import org.e2ee.data.userKeys.UserKeys

@Entity(
    tableName = "signed_pre_keys",
    foreignKeys = [
        ForeignKey(
            entity = UserKeys::class,
            parentColumns = ["id"],
            childColumns = ["localUserId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["localUserId"])
    ]
)
data class SignedPreKeys(
    @PrimaryKey
    val signedPreKeyId: String,

    val localUserId: Int = 1,

    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val signature: ByteArray,

    val createdAt: Long = System.currentTimeMillis(),

    // Active lifetime: 30 days
    val expiresAt: Long = createdAt + 30L * 24 * 60 * 60 * 1000,

    // After it becomes inactive, keep it for 48 hours
    val deleteAfter: Long? = null,

    val uploaded: Boolean = false,
    val active: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedPreKeys

        if (localUserId != other.localUserId) return false
        if (createdAt != other.createdAt) return false
        if (expiresAt != other.expiresAt) return false
        if (deleteAfter != other.deleteAfter) return false
        if (uploaded != other.uploaded) return false
        if (active != other.active) return false
        if (signedPreKeyId != other.signedPreKeyId) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = localUserId
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + expiresAt.hashCode()
        result = 31 * result + (deleteAfter?.hashCode() ?: 0)
        result = 31 * result + uploaded.hashCode()
        result = 31 * result + active.hashCode()
        result = 31 * result + signedPreKeyId.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}