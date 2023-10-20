package com.example.springauthservertest

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TestController {
  @GetMapping("/me")
  fun getInfo(): UserInfoResponse =
    UserInfoResponse("sally")

  data class UserInfoResponse(
    val nickname: String
  )
}