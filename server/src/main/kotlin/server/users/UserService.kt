package server.users

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service

@Service
class UserService(
    private final val userRepository: UserRepository
) {
    fun getUsers()= ResponseEntity.ok(userRepository.findAll())
}