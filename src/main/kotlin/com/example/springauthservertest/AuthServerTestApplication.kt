package com.example.springauthservertest

import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.crypto.password.PasswordEncoder

@SpringBootApplication
class AuthServerTestApplication(
  private val memberRepository: MemberRepository,
  private val passwordEncoder: PasswordEncoder
): CommandLineRunner {
  override fun run(vararg args: String?) {
    memberRepository.deleteAll().subscribe()

    memberRepository.saveAll(
      listOf(
        Member(
          username = "user",
          secret = passwordEncoder.encode("pw"),
          type = Member.SocialType.NONE
        ), Member(
          username = "user2",
          secret = passwordEncoder.encode("pw2"),
          type = Member.SocialType.NONE
        )
      )
    ).subscribe()

    memberRepository.findAll().map { println(it) }.subscribe()
  }
}

fun main(args: Array<String>) {
  runApplication<AuthServerTestApplication>(*args)
}
