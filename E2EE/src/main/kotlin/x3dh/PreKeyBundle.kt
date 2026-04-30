package x3dh

import java.security.PrivateKey
import java.security.PublicKey


data class PreKeyBundle(
    val IKpub : ByteArray,
    val SPKpub : ByteArray,
    val OPKpub : Map<String, ByteArray> ?,
    val signature : ByteArray,
    val IKsigPub : ByteArray
)



