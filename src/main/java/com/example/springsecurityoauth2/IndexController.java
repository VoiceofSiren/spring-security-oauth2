package com.example.springsecurityoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {

        ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

        String clientId = keycloakClientRegistration.getClientId();
        System.out.println("clientId = " + clientId);

        String redirectUri = keycloakClientRegistration.getRedirectUri();
        System.out.println("redirectUri = " + redirectUri);


        return "index";
    }
}
