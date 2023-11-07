package com.example.springauthservertest.oauth

import com.example.springauthservertest.Member
import com.example.springauthservertest.MemberService
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.util.Locale

@Service
class OidcUserService(private val memberService: MemberService): ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {
  data class CustomOidcUser(
    override val username: String,
    val attributes2: Map<String, Any>,
    val claims2: Map<String, Any>,
    val userInfo2: OidcUserInfo,
    val idToken2: OidcIdToken
  ): OAuth2UserService.CustomOAuth2User(username, attributes2),OidcUser {
    override fun getName(): String = this.username
    override fun getAttributes(): Map<String, Any> = this.attributes2
    override fun getAuthorities(): List<GrantedAuthority> = emptyList()
    override fun getClaims(): Map<String, Any> = this.claims2
    override fun getUserInfo(): OidcUserInfo = this.userInfo2
    override fun getIdToken(): OidcIdToken = this.idToken2
  }

  override fun loadUser(userRequest: OidcUserRequest): Mono<OidcUser> {
    val delegate = OidcReactiveOAuth2UserService()
    val socialType = Member.SocialType.valueOf(userRequest.clientRegistration.registrationId.uppercase(Locale.getDefault()))

    return delegate.loadUser(userRequest)
      .flatMap { oidcUser ->
        val username = oidcUser.attributes["email"] as String

        this.memberService.findSocialMember(socialType, username)
          .map {
            CustomOidcUser(
              username = username,
              attributes2 = oidcUser.attributes,
              claims2 = oidcUser.claims,
              userInfo2 = oidcUser.userInfo,
              idToken2 = oidcUser.idToken
            )
          }
      }
  }
}
