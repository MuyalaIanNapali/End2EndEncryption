package org.e2ee.crypto.x3dh


data class PreKeyBundle(
    val IKpub : ByteArray,
    val SPKpub : ByteArray,
    val OPKpub : Map<String, ByteArray> ?,
    val signature : ByteArray,
    val IKsigPub : ByteArray
)



