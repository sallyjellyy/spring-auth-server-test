package com.example.springauthservertest

import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.crypto.password.PasswordEncoder

@SpringBootApplication
class AuthServerTestApplication(
  private val userRepository: CustomUserRepository,
  private val passwordEncoder: PasswordEncoder
): CommandLineRunner {
  override fun run(vararg args: String?) {
    userRepository.deleteAll()

    userRepository.save(
      CustomUser(
        key = "user",
//        secret = passwordEncoder.encode("pw"),
        secret= "{noop}pw",
        authenticated = false
      )
    )

    userRepository.findAll().forEach { println(it) }
  }
}

fun main(args: Array<String>) {
  runApplication<AuthServerTestApplication>(*args)
}
