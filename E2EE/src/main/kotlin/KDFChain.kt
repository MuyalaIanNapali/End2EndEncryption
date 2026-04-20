package org.example


class KDFChain: KDF{
    override fun kdfRootKey(rootKey: ByteArray, dhOutputKey: ByteArray): Pair<ByteArray,ByteArray> {
        val derivedKey = HKDF.deriveKey(
            dhOutputKey,
            rootKey,
            "diffie-hellman ratchet".toByteArray(),
            64
        )
        val newRootKey = derivedKey.copyOfRange(0,32)
        val chainKey = derivedKey.copyOfRange(32,64)

        return Pair(newRootKey,chainKey)
    }

    override fun kdfChainKey(kdfChainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val derivedKey = HKDF.deriveKey(
            kdfChainKey,
            salt=null,
            "diffie-hellman ratchet".toByteArray(),
            64
        )

        val newChainKey = derivedKey.copyOfRange(0,32)
        val messageKey = derivedKey.copyOfRange(32,64)
        return Pair(newChainKey,messageKey)
    }

}