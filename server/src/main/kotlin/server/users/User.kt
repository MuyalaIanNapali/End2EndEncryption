package server.users

import jakarta.persistence.*
import jakarta.validation.constraints.Email
import org.hibernate.annotations.CreationTimestamp
import org.hibernate.annotations.UpdateTimestamp
import java.time.LocalDateTime

@Entity
@Table(name = "users")
class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,

    @Column(name = "username", nullable = false, unique = true)
    var username: String,

    @Email
    @Column(name = "email", nullable = false, unique = true)
    var email: String,

    @Column(name = "password", nullable = false)
    var password: String,

    @Column(name = "avatar_url")
    var avatarUrl: String? = null,


    @Column(name = "last_seen")
    var lastSeen: LocalDateTime? = null,

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    var createdAt: LocalDateTime? = null,

    @UpdateTimestamp
    @Column(name = "updated_at")
    var updatedAt: LocalDateTime? = null


)

fun User.isOnline(now: LocalDateTime): Boolean {
    return lastSeen?.isAfter(now.minusMinutes(2)) == true
}