package server.keymanager.opk

import jakarta.persistence.LockModeType
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Lock
import org.springframework.data.jpa.repository.Query

interface OneTimePreKeysRepository: JpaRepository<OneTimePreKeys, Long> {

    fun countByUserIdAndUsedFalse(userId: Long): Long

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query(
        """
            SELECT o FROM OneTimePreKeys o
            WHERE o.userId = :userId AND o.used= false 
            ORDER BY o.id ASC LIMIT 1
        """
    )
    fun getNextAvailableOPK(userId: Long): OneTimePreKeys?

    fun deleteByUserIdAndUsedFalse(userId: Long)
}