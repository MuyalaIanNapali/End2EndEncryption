package server.keymanager

import org.springframework.http.ResponseEntity
import server.keymanager.dto.PreKeyBundle
import server.keymanager.dto.PreKeyVerification
import server.keymanager.dto.SignedPreKeyBundle
import server.keymanager.dto.UpdateSignedPreKeyBundle

fun UserPublicKeys.updateFromSPK(updateSignedPreKeyBundle: UpdateSignedPreKeyBundle) {
    updateSignedPreKeyBundle.keyId.let { this.signedPreKeyId = it }
    updateSignedPreKeyBundle.signedPreKey.let { this.signedPreKey = it}
    updateSignedPreKeyBundle.signature.let { this.signature = it }
}

fun UserPublicKeys.updateFromPreKeyBundle(preKeyBundle: PreKeyBundle) {
    preKeyBundle.identityKey.let { this.identityKey= it }
    preKeyBundle.identityKeySigning.let {this.identityKeySigning = it}
    preKeyBundle.signedPreKeyBundle.keyId.let { this.signedPreKeyId = it }
    preKeyBundle.signedPreKeyBundle.signedPreKey.let { this.signedPreKey = it}
    preKeyBundle.signedPreKeyBundle.signature.let { this.signature = it }
}

fun UserPublicKeys.toPreKeyVerification() = PreKeyVerification(
    identityKeySigning = identityKeySigning,
    signedPreKeyBundle = SignedPreKeyBundle(
        keyId = signedPreKeyId,
        signedPreKey = signedPreKey,
        signature = signature
    )
)