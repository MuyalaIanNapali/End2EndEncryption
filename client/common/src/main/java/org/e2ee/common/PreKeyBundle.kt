package org.e2ee.common

data class PreKeyBundle(
    val IKpub : ByteArray,
    val SPKpub : Pair<String,ByteArray>,
    val OPKpub : Map<String, ByteArray> ?,
    val signature : ByteArray,
    val IKsigPub : ByteArray
)