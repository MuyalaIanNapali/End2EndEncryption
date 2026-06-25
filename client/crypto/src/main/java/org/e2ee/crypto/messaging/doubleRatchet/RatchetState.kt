package org.e2ee.crypto.messaging.doubleRatchet

import org.e2ee.common.RatchetStateDto
import org.e2ee.common.SkippedMessageKeyId
import org.e2ee.crypto.messaging.encryptDecrypt.EncryptionAndDecryptionUtility
import java.security.KeyPair
import java.security.PublicKey
import kotlin.collections.mapValues


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

fun RatchetStateHE.toDto(): RatchetStateDto {
    return RatchetStateDto(
        DHs = Pair(
            DHs.public.encoded,
            DHs.private.encoded
        ),
        DHr = DHr?.encoded,
        RK = RK.copyOf(),
        CKs = CKs?.copyOf(),
        CKr = CKr?.copyOf(),
        Ns = Ns,
        Nr = Nr,
        PN = PN,
        MKSKIPPED = MKSKIPPED.mapValues { it.value.copyOf() }.toMutableMap() ,
        HKs = HKs?.copyOf(),
        HKr = HKr?.copyOf(),
        NHKs = NHKs?.copyOf(),
        NHKr = NHKr?.copyOf()
    )
}

fun RatchetStateDto.toRatchetStateHE(): RatchetStateHE {
    return RatchetStateHE(
        DHs = KeyPair(
            EncryptionAndDecryptionUtility().decodePublicKey(DHs.first),
            EncryptionAndDecryptionUtility().decodePrivateKey(DHs.second)
        ),
        DHr = DHr?.let { EncryptionAndDecryptionUtility().decodePublicKey(it) },
        RK = RK.copyOf(),
        CKs = CKs?.copyOf(),
        CKr = CKr?.copyOf(),
        Ns = Ns,
        Nr = Nr,
        PN = PN,
        MKSKIPPED = MKSKIPPED.mapValues { it.value.copyOf() }.toMutableMap(),
        HKs = HKs?.copyOf(),
        HKr = HKr?.copyOf(),
        NHKs = NHKs?.copyOf(),
        NHKr = NHKr?.copyOf()
    )
}


