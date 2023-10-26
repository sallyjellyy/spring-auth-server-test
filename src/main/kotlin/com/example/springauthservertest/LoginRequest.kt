package com.example.springauthservertest

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

//@JsonIgnoreProperties(ignoreUnknown = true)
data class LoginRequest(
  val username: String,
  val password: String
)