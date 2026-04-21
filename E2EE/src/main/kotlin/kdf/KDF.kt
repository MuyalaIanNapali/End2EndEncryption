package org.example

interface KDF {
    fun kdfRootKey(rootKey: ByteArray, dhOutputKey: ByteArray): Pair<ByteArray,ByteArray>

    fun kdfChainKey(kdfChainKey: ByteArray): Pair<ByteArray, ByteArray>
}