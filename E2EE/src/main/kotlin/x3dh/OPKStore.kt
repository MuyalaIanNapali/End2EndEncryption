package org.example.x3dh

import java.security.PrivateKey

class OPKStore {
    private val store = mutableMapOf<String, PrivateKey>()

    fun add(id: String, key: PrivateKey) {
        store[id] = key
    }



    fun consume(id: String): PrivateKey? = store.remove(id)

    fun size() = store.size
    fun get(opkId: String) : PrivateKey? = store[opkId]
}