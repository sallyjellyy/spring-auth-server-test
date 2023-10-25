package com.example.springauthservertest

import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
internal class TestController {
  @GetMapping("/")
  fun home(): String = "Welcome home"

  @GetMapping("/user")
  fun user(authentication: Authentication): String = "Welcome ${authentication.name}"

  @GetMapping("/admin")
  fun admin(authentication: Authentication): String = "Welcome admin"
}