package org.e2ee.data.local.ratchetStates

import org.e2ee.common.RatchetStateDto
import org.e2ee.common.SkippedMessageKey
import org.e2ee.common.SkippedMessageKeyId

fun mkSkippedToList(
    map: MutableMap<SkippedMessageKeyId, ByteArray>
): List<SkippedMessageKey> {
    return map.map { (id, messageKey) ->
        SkippedMessageKey(
            id = SkippedMessageKeyId(
                headerKey = id.headerKey.copyOf(),
                messageNumber = id.messageNumber
            ),
            messageKey = messageKey.copyOf()
        )
    }
}

fun listToMkSkipped(
    list: List<SkippedMessageKey>
): MutableMap<SkippedMessageKeyId, ByteArray> {
    return list.associate { skipped ->
        SkippedMessageKeyId(
            headerKey = skipped.id.headerKey.copyOf(),
            messageNumber = skipped.id.messageNumber
        ) to skipped.messageKey.copyOf()
    }.toMutableMap()
}

fun RatchetStateDto.toRatchetStates(sessionId: String): RatchetStates {
    return RatchetStates(
        sessionId = sessionId,
        DHsPublic = this.DHs.first,
        DHsPrivate = this.DHs.second,
        DHr = this.DHr,
        RK = this.RK,
        CKs = this.CKs,
        CKr = this.CKr,
        Ns = this.Ns,
        Nr = this.Nr,
        PN = this.PN,
        MKSKIPPED = SkippedMessageKeysCodec.encodeList(
            mkSkippedToList(this.MKSKIPPED)
        ),
        HKs = this.HKs,
        HKr = this.HKr,
        NHKs = this.NHKs,
        NHKr = this.NHKr
    )
}

fun RatchetStates.toRatchetStateDto(): RatchetStateDto {
    return RatchetStateDto(
        DHs = Pair(this.DHsPublic, this.DHsPrivate),
        DHr = this.DHr,
        RK = this.RK,
        CKs = this.CKs,
        CKr = this.CKr,
        Ns = this.Ns,
        Nr = this.Nr,
        PN = this.PN,
        MKSKIPPED = listToMkSkipped(
            SkippedMessageKeysCodec.decodeList(
                this.MKSKIPPED
            )
        ),
        HKs = this.HKs,
        HKr = this.HKr,
        NHKs = this.NHKs,
        NHKr = this.NHKr
    )
}