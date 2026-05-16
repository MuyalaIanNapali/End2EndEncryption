package org.e2ee.crypto.doubleRatchet

import org.e2ee.crypto.entities.SkippedMessageKeyId
import java.security.KeyPair
import java.security.PublicKey


data class RatchetStateHE(
    var DHs: KeyPair,
    var DHr: PublicKey?,

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

internal fun RatchetStateHE.deepCopy(): RatchetStateHE {
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

/*fun deepCopyMKSkipped(
    original: MutableMap<SkippedMessageKeyId, ByteArray>
): MutableMap<SkippedMessageKeyId, ByteArray> {
    val newMap = mutableMapOf<SkippedMessageKeyId, ByteArray>()

    for ((k, v) in original) {
        val copiedKey = SkippedMessageKeyId(
            headerKey = k.headerKey.copyOf(),
            messageNumber = k.messageNumber
        )

        newMap[copiedKey] = v.copyOf()
    }

    return newMap
}

 */

fun deepCopyMKSkipped(
    original: MutableMap<SkippedMessageKeyId, ByteArray>
): MutableMap<SkippedMessageKeyId, ByteArray> {
    return original.mapKeys { (key, _) ->
        SkippedMessageKeyId(
            headerKey = key.headerKey.copyOf(),
            messageNumber = key.messageNumber
        )
    }.mapValues { (_, value) ->
        value.copyOf()
    }.toMutableMap()
}