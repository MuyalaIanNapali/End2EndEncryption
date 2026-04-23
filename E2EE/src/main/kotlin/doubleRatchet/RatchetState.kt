package org.example.doubleRatchet

import java.security.KeyPair
import java.security.PublicKey

data class RatchetState(
    var DHs: KeyPair,
    var DHr: PublicKey?,

    var RK: ByteArray,
    var CKs: ByteArray?,
    var CKr: ByteArray?,

    var Ns: Int,
    var Nr: Int,
    var PN: Int,

    val MKSKIPPED: MutableMap<Pair<PublicKey, Int>, ByteArray> = mutableMapOf(),


    val MAX_SKIP: Int = 10
)

data class RatchetStateHE(
    var DHs: KeyPair,
    var DHr: PublicKey?,

    var RK: ByteArray,
    var CKs: ByteArray?,
    var CKr: ByteArray?,

    var Ns: Int,
    var Nr: Int,
    var PN: Int,

    val MKSKIPPED: MutableMap<Pair<ByteArray, Int>, ByteArray> = mutableMapOf(),

    var HKs: ByteArray?,
    var HKr: ByteArray?,
    var NHKs: ByteArray?,
    var NHKr: ByteArray?,

    val MAX_SKIP: Int = 10
)