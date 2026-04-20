package org.example

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

    val MKSKIPPED: MutableMap<Pair<ByteArray, Int>, ByteArray> = mutableMapOf()
)