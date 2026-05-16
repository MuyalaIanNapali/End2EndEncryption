package org.e2ee.data.ratchetStates

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "ratchet_states")
data class RatchetStates(
    @PrimaryKey
    val sessionId: String,
    val DHsPublic: ByteArray,    //KeyPair
    val DHsPrivate: ByteArray,
    val DHr: ByteArray?=null,                              //PublicKey?

    val RK: ByteArray,
    val CKs: ByteArray?=null,
    val CKr: ByteArray?=null,

    val Ns: Int,
    val Nr: Int,
    val PN: Int,


    //val MKSKIPPED: MutableMap<Pair<ByteArray, Int>, ByteArray> = mutableMapOf(),

    var HKs: ByteArray?=null,
    var HKr: ByteArray?=null,
    var NHKs: ByteArray?=null,
    var NHKr: ByteArray?=null,

    val MAX_SKIP: Int = 100
)
