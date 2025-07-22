package com.nhnacademy.authservice.factory;

import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.exception.InvalidOAuth2ProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class OAuth2MemberClientFactory {
    private final Map<String, OAuth2MemberClient> clientMap;

    @Autowired
    public OAuth2MemberClientFactory(List<OAuth2MemberClient> clients) {
        this.clientMap = clients.stream()
                .collect(Collectors.toMap(
                        c -> {
                            String name = c.getClass().getAnnotation(Component.class).value();
                            return name.replace("MemberClient", "");
                        },
                        c -> c
                ));
    }

    public OAuth2MemberClient getClient(String provider) {
        OAuth2MemberClient client = clientMap.get(provider);
        if (client == null) {
            throw new InvalidOAuth2ProviderException(provider);
        }
        return client;
    }
}