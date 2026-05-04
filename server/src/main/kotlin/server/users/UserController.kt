package server.users

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody

@CrossOrigin
@RestController
@RequestMapping(value = ["api/v1/users"], produces = ["application/json"])
class UserController(private val userService: UserService) {

    @GetMapping
    fun getUsers(): ResponseEntity<List<Users>> {
        return userService.getUsers()
    }

    @PostMapping
    fun createUser(@RequestBody @Valid user: Users): ResponseEntity<Users> {
        return userService.createUser(user)
    }
}