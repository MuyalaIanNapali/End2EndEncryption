package org.e2ee.common

data class PreKeyBundle(
    val IKpub : ByteArray,
    val SPKid : String,
    val SPKpub : Pair<Int?,ByteArray>,
    val OPKpub : Map<String, ByteArray> ?,
    val signature : ByteArray,
    val IKsigPub : ByteArray
)