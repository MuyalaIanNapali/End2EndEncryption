package org.e2ee.crypto.x3dh


data class PreKeyBundle(
    val IKpub : ByteArray,
    val SPKpub : Pair<Int?,ByteArray>,
    val OPKpub : Map<String, ByteArray> ?,
    val signature : ByteArray,
    val IKsigPub : ByteArray
)



