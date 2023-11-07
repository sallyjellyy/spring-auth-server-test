package com.example.springauthservertest.oauth

import com.example.springauthservertest.Member
import com.example.springauthservertest.MemberService
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.util.Locale

@Service
class OAuth2UserService(private val memberService: MemberService):
  ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {
  open class CustomOAuth2User(
    open val username: String,
    val attributes1: Map<String, Any>
  ): OAuth2User {
    override fun getName(): String = this.username
    override fun getAttributes(): Map<String, Any> = this.attributes1
    override fun getAuthorities(): List<GrantedAuthority> = emptyList()
  }

  override fun loadUser(userRequest: OAuth2UserRequest): Mono<OAuth2User> {
    val delegate = DefaultReactiveOAuth2UserService()
    val socialType = Member.SocialType.valueOf(userRequest.clientRegistration.registrationId.uppercase(Locale.getDefault()))

    return delegate.loadUser(userRequest)
      .flatMap { oauth2User ->
        val attributes = oauth2User.attributes

        this.memberService.findSocialMember(username = attributes["email"] as String, type = socialType)
          .map { member ->
            CustomOAuth2User(member.username, attributes)
          }
      }
  }
}
