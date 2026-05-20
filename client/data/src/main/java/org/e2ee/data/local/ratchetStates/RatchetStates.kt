package org.e2ee.data.local.ratchetStates

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "ratchet_states")
data class RatchetStates(
    @PrimaryKey
    val sessionId: String,
    val DHsPublic: ByteArray,
    val DHsPrivate: ByteArray,
    val DHr: ByteArray?=null,

    val RK: ByteArray,
    val CKs: ByteArray?=null,
    val CKr: ByteArray?=null,

    val Ns: Int,
    val Nr: Int,
    val PN: Int,


    val MKSKIPPED: ByteArray = ByteArray(0),

    var HKs: ByteArray?=null,
    var HKr: ByteArray?=null,
    var NHKs: ByteArray?=null,
    var NHKr: ByteArray?=null,

    val MAX_SKIP: Int = 100
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RatchetStates

        if (Ns != other.Ns) return false
        if (Nr != other.Nr) return false
        if (PN != other.PN) return false
        if (MAX_SKIP != other.MAX_SKIP) return false
        if (sessionId != other.sessionId) return false
        if (!DHsPublic.contentEquals(other.DHsPublic)) return false
        if (!DHsPrivate.contentEquals(other.DHsPrivate)) return false
        if (!DHr.contentEquals(other.DHr)) return false
        if (!RK.contentEquals(other.RK)) return false
        if (!CKs.contentEquals(other.CKs)) return false
        if (!CKr.contentEquals(other.CKr)) return false
        if (!MKSKIPPED.contentEquals(other.MKSKIPPED)) return false
        if (!HKs.contentEquals(other.HKs)) return false
        if (!HKr.contentEquals(other.HKr)) return false
        if (!NHKs.contentEquals(other.NHKs)) return false
        if (!NHKr.contentEquals(other.NHKr)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Ns
        result = 31 * result + Nr
        result = 31 * result + PN
        result = 31 * result + MAX_SKIP
        result = 31 * result + sessionId.hashCode()
        result = 31 * result + DHsPublic.contentHashCode()
        result = 31 * result + DHsPrivate.contentHashCode()
        result = 31 * result + (DHr?.contentHashCode() ?: 0)
        result = 31 * result + RK.contentHashCode()
        result = 31 * result + (CKs?.contentHashCode() ?: 0)
        result = 31 * result + (CKr?.contentHashCode() ?: 0)
        result = 31 * result + MKSKIPPED.contentHashCode()
        result = 31 * result + (HKs?.contentHashCode() ?: 0)
        result = 31 * result + (HKr?.contentHashCode() ?: 0)
        result = 31 * result + (NHKs?.contentHashCode() ?: 0)
        result = 31 * result + (NHKr?.contentHashCode() ?: 0)
        return result
    }
}