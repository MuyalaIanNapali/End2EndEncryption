package server.keymanager

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.intellij.lang.annotations.Identifier
import java.security.PublicKey

@Entity
@Table(name = "user_public_keys")
class UserPublicKeys (
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false,unique = true)
    val userKeysId: Long?=null,

    @Column(name = "user_id", nullable = false)
    val userId: Long,

    @Column(name = "signed_pre_key_id", nullable = false)
    var signedPreKeyId: Long,

    @Column(name="signed_pre_key", nullable = false)
    var signedPreKey: ByteArray,

    @Column(name="signature", nullable = false)
    var signature: ByteArray,

    @Column(name = "IK", nullable = false)
    var identityKey: ByteArray,

    @Column(name = "IKsig", nullable = false)
    var identityKeySigning: ByteArray,
)