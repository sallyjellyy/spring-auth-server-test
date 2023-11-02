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
    userRepository.deleteAll().subscribe()

    userRepository.saveAll(
      listOf(
        CustomUser(
          key = "user",
          secret = passwordEncoder.encode("pw"),
          authenticated = false
        ), CustomUser(
          key = "user2",
          secret = passwordEncoder.encode("pw2"),
          authenticated = false
        )
      )
    ).subscribe()

    userRepository.findAll().map { println(it) }.subscribe()
  }
}

fun main(args: Array<String>) {
  runApplication<AuthServerTestApplication>(*args)
}
