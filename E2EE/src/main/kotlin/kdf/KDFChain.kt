package kdf


class KDFChain: KDF{

    override fun kdfRootKey(
        rootKey: ByteArray,
        dhOutputKey: ByteArray
    ): Pair<ByteArray,ByteArray> {

        return HKDF.rootHKDF(
            dhOutputKey,
            rootKey,
            "diffie-hellman ratchet".toByteArray(),
            64
        )

    }

    override fun kdfChainKey(
        kdfChainKey: ByteArray
    ): Pair<ByteArray, ByteArray> {

        return HKDF.chainHKDF(kdfChainKey)

    }

    fun kdfRootKeyHeaderEncryption(
        rootKey: ByteArray,
        dhOutputKey: ByteArray
    ): Triple<ByteArray,ByteArray,ByteArray> {

        return HKDF.rootHEHKDF(
            dhOutputKey,
            rootKey,
            "diffie-hellman ratchet".toByteArray(),
            96
        )

    }

}