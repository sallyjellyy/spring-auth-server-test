package com.example.springauthservertest

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class AuthServerTestApplication

fun main(args: Array<String>) {
  runApplication<AuthServerTestApplication>(*args)
}
