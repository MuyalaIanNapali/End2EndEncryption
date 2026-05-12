package server.keymanager.opk

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

@Entity
@Table(name = "one_time_pre_keys")
class OneTimePreKeys(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    val id: Long? = null,

    @Column(name = "user_opk_id", nullable = false)
    val keyId: String,

    @Column(name = "user_id", nullable = false)
    val userId: Long,

    @Column(name = "key", nullable = false)
    val key: ByteArray,

    @Column(name = "used", nullable = false)
    var used: Boolean = false

)