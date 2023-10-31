package com.example.springauthservertest

import com.nimbusds.jwt.JWT
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
internal class TestController(private val loginService: LoginService) {

  @GetMapping("/")
  fun home(): String = "Welcome home"

  @GetMapping("/user")
  fun user(authentication: Authentication): String = "Welcome ${authentication.name}"

  @GetMapping("/admin")
  fun admin(authentication: Authentication): String = "Welcome admin"

  @PostMapping("/login")
  fun login(@RequestBody req: LoginReq): Mono<String> =
    this.loginService.login(req)
}
