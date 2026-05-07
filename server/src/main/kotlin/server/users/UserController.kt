package server.users

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import server.jwt.JWTService
import server.jwt.RefreshRequest
import server.jwt.RefreshResponse
import server.jwt.RefreshTokenService
import server.users.dto.LoginRequest
import server.users.dto.UserRequest
import server.users.dto.UserResponse

@CrossOrigin
@RestController
@RequestMapping(value = ["api/v1/users"], produces = ["application/json"])
class UserController(
    private val userService: UserService
) {

    @GetMapping
    fun getUsers(): ResponseEntity<List<User>> {
        return userService.getUsers()
    }

    @PostMapping(value = ["/createUser"])
    fun createUser(@RequestBody @Valid userRequest: UserRequest): ResponseEntity<UserResponse> {
        return userService.createUser(userRequest)
    }

    @PostMapping(value = ["/login"])
    fun loginUser(@RequestBody @Valid request: LoginRequest): ResponseEntity<Any> {
        return userService.loginUser(request)
    }

    @GetMapping(value = ["/{username}"], produces = ["application/json"])
    fun getUserByUsername(@PathVariable username: String): ResponseEntity<UserResponse> {
        return userService.findUserByUsername(username)
    }

    @PostMapping("/logout/{username}")
    fun logoutUser(@PathVariable username: String): ResponseEntity<Void> {
        return userService.logoutUser(username)
    }

    @PostMapping("/refresh")
    fun refresh(@RequestBody request: RefreshRequest): ResponseEntity<RefreshResponse> {

        return userService.refreshToken(request.refreshToken)
    }
}
