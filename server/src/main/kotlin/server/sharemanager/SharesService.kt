package server.sharemanager

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import server.exceptionHandler.ShareNotFoundException
import server.exceptionHandler.UserNotFoundException
import server.users.UserRepository
import java.time.LocalDateTime

@Service
class SharesService (
    private val sharesRepository: SharesRepository,
    private val userRepository: UserRepository
){
    fun getUserShare(username: String): SharesResponse {
        val user = userRepository.findByUsername(username)
            ?: throw UserNotFoundException()

        val share = sharesRepository.findByUserId(requireNotNull(user.id))
            ?: throw ShareNotFoundException()

        return share.toSharesResponse()
    }

    fun createOrUpdateUserShare(username: String,sharesRequest: UpdateSharesRequest) {
        val user = userRepository.findByUsername(username)
        ?: throw UserNotFoundException()
        val share = sharesRepository.findByUserId(requireNotNull(user.id))

        if (share == null) {
            val newShare = Shares(
                userId = requireNotNull(user.id),
                share = sharesRequest.share,
                createdAt = LocalDateTime.now(),
                updatedAt = LocalDateTime.now()
            )
            sharesRepository.save(newShare)
        } else {
            share.updateFrom(sharesRequest)
            sharesRepository.save(share)
        }

    }
}