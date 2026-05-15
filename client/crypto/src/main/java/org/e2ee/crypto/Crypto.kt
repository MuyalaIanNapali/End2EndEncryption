package org.e2ee.crypto

import org.e2ee.crypto.encryptDecrypt.EllipticCurveDiffieHellman
import org.e2ee.crypto.x3dh.PreKeyBundle
import org.e2ee.crypto.x3dh.SignatureHelper
import org.e2ee.crypto.x3dh.X3DHKeyManager
import org.e2ee.crypto.x3dh.X3dh


fun createAccount(): Pair<X3DHKeyManager,PreKeyBundle>{
    val userKeyManager = X3DHKeyManager(
        EllipticCurveDiffieHellman(),
        SignatureHelper()
    )
    val userX3dh = X3dh(
        EllipticCurveDiffieHellman(),
        SignatureHelper(),
        userKeyManager
    )

    val userPreKeyBundle = userX3dh.publishKeys()
    return Pair(userKeyManager,userPreKeyBundle)

}

class Crypto {
}