package kdf



class KDFChain: KDF{

    override fun kdfChainKey(
        kdfChainKey: ByteArray
    ): Pair<ByteArray, ByteArray> {

        return HKDF.chainHKDF(kdfChainKey)

    }

    override fun kdfRootKey(
        rootKey: ByteArray,
        dhOutputKey: ByteArray
    ): Triple<ByteArray,ByteArray,ByteArray> {

        return HKDF.rootHKDF(
            dhOutputKey,
            rootKey,
            "diffie-hellman ratchet".toByteArray(),
            96
        )
    }

}