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

    override fun kdfX3DH(
        inputKey: ByteArray,
        info: ByteArray
    ) : ByteArray {
        val F = ByteArray(32) {0xFF.toByte()}
        val salt = ByteArray(32) { 0x00 }
        val ikm = F + inputKey

        return HKDF.X3dhHKDF(
            ikm,
            salt,
            info,
            32
        )
    }

}