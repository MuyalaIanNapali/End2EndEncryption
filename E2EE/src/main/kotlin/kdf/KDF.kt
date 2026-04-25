package kdf

interface KDF {
    fun kdfRootKey(rootKey: ByteArray, dhOutputKey: ByteArray): Triple<ByteArray,ByteArray,ByteArray>

    fun kdfChainKey(kdfChainKey: ByteArray): Pair<ByteArray, ByteArray>
}