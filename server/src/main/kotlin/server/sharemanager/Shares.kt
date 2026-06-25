package server.sharemanager

import jakarta.persistence.Column
import jakarta.persistence.Embedded
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDateTime

@Entity
@Table(name = "shares")
class Shares(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,

    @Column(name = "user_id", nullable = false,unique = true)
    var userId: Long,

    @Column(name= "share", nullable = false)
    @Embedded
    var share: ShareDto,

    @Column(name = "created_at", nullable = false)
    val createdAt: LocalDateTime? = null,

    @Column(name = "updated_at", nullable = false)
    val updatedAt: LocalDateTime? = null
)

fun Shares.toSharesResponse() = SharesResponse(
    userId = userId,
    share = share
)

fun Shares.updateFrom(request: UpdateSharesRequest) {
    request.share.let { share = it }
}
