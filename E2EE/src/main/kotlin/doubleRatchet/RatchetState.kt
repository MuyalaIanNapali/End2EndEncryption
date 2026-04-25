package doubleRatchet

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

fun RatchetStateHE.deepCopy(): RatchetStateHE {
    return RatchetStateHE(
        DHs = this.DHs,
        DHr = this.DHr,
        RK = this.RK.copyOf(),
        CKs = this.CKs?.copyOf(),
        CKr = this.CKr?.copyOf(),
        Ns = this.Ns,
        Nr = this.Nr,
        PN = this.PN,
        MKSKIPPED = deepCopyMKSkipped(this.MKSKIPPED),
        HKs = this.HKs?.copyOf(),
        HKr = this.HKr?.copyOf(),
        NHKs = this.NHKs?.copyOf(),
        NHKr = this.NHKr?.copyOf()
    )
}

fun deepCopyMKSkipped(
    original: MutableMap<Pair<ByteArray, Int>, ByteArray>
): MutableMap<Pair<ByteArray, Int>, ByteArray> {
    val newMap = mutableMapOf<Pair<ByteArray, Int>, ByteArray>()
    for ((k, v) in original) {
        newMap[k] = v.copyOf()
    }
    return newMap
}