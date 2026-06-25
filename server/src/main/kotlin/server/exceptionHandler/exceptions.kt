package server.exceptionHandler

class UserNotFoundException(message: String = "User not found") : RuntimeException(message)

class UsernameAlreadyTakenException(message: String = "Username already taken") : RuntimeException(message)

class EmailAlreadyTakenException(message: String = "Email already taken") : RuntimeException(message)

class InvalidCredentialsException(message: String = "Invalid username or password") : RuntimeException(message)

class UserPublicKeyNotFoundException(message: String = "User public key not found") : RuntimeException(message)

class PreKeyBundlesNotFoundException(message: String = "Pre-key-bundle not found") : RuntimeException(message)

class InvalidRefreshTokenException(message: String = "Invalid refresh token") : RuntimeException(message)

class TokenExpiredException(message: String = "Token expired") : RuntimeException(message)

class ShareNotFoundException(message: String = "Share not found") : RuntimeException(message)