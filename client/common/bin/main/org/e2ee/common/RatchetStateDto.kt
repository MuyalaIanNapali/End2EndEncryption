package org.e2ee.common

data class RatchetStateDto(
    var DHs: Pair<ByteArray, ByteArray>,    //KeyPair
    var DHr: ByteArray?,                              //PublicKey?

    var RK: ByteArray,
    var CKs: ByteArray?,
    var CKr: ByteArray?,

    var Ns: Int,
    var Nr: Int,
    var PN: Int,

    val MKSKIPPED: MutableMap<SkippedMessageKeyId, ByteArray> = mutableMapOf(),

    var HKs: ByteArray?,
    var HKr: ByteArray?,
    var NHKs: ByteArray?,
    var NHKr: ByteArray?,

    val MAX_SKIP: Int = 10
)