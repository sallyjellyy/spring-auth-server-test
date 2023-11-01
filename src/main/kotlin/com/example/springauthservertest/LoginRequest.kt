package com.example.springauthservertest

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

data class LoginRequest(
  val username: String,
  val password: String
)