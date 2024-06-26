package com.example.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
public class IndexController {

    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {

/*        ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

        String clientId = keycloakClientRegistration.getClientId();
        System.out.println("clientId = " + clientId);

        String redirectUri = keycloakClientRegistration.getRedirectUri();
        System.out.println("redirectUri = " + redirectUri);*/


        return "index";
    }

    @GetMapping("/user")
    public OAuth2User user(Authentication authentication) {
        //Authentication newAuthentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        return (OAuth2User) oAuth2AuthenticationToken.getPrincipal();
    }

    @GetMapping("/oauth2User")
    public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
        System.out.println("oAuth2User = " + oAuth2User);
        return oAuth2User;
    }

    @GetMapping("/oidcUser")
    public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        System.out.println("oidcUser = " + oidcUser);
        return oidcUser;
    }

    @GetMapping("/user-token")
    public OAuth2User userToken(String accessToken) {
        ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);
        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(keycloakClientRegistration, oAuth2AccessToken);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);
        return oAuth2User;
    }

    @GetMapping("/oidc-token")
    public OidcUser oidc(String accessToken, String idToken) {
        ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost/realms/oauth2");
        idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
        idTokenClaims.put("preferred_username", "user");

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims);
        OidcUserRequest oidcUserRequest = new OidcUserRequest(keycloakClientRegistration, oAuth2AccessToken, oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(oidcUserRequest);
        return oidcUser;
    }
}
