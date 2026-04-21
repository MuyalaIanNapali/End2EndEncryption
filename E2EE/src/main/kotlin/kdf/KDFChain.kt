package org.example


class KDFChain: KDF{
    override fun kdfRootKey(rootKey: ByteArray, dhOutputKey: ByteArray): Pair<ByteArray,ByteArray> {

        return HKDF.rootHKDF(
            dhOutputKey,
            rootKey,
            "diffie-hellman ratchet".toByteArray(),
            64
        )
    }

    override fun kdfChainKey(kdfChainKey: ByteArray): Pair<ByteArray, ByteArray> {
        return HKDF.chainHKDF(kdfChainKey,)
    }

}