package com.example.springauthservertest

import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.encrypt.TextEncryptor
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

@Component
internal class CustomAuthenticationProvider(
    private val userService: UserService,
    private val passwordEncoder: PasswordEncoder
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val key = authentication.name
        val secret = authentication.credentials.toString()
        val user = this.userService.findByUsername(key).block()

        println("provider here!**********************************")

        if (user == null || !passwordEncoder.matches(secret, user.password)) {
            throw Exception()
        }

        return UsernamePasswordAuthenticationToken(user, secret, user.authorities)
    }

    override fun supports(authentication: Class<*>?): Boolean =
        authentication == UsernamePasswordAuthenticationToken::class.java
}
