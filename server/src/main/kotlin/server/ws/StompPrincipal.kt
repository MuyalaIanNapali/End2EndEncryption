package server.ws

import java.security.Principal

class StompPrincipal(
    private val userId: String
) : Principal {
    override fun getName(): String = userId
}