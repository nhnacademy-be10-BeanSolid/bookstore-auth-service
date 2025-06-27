package com.nhnacademy.authservice.factory;

import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class OAuth2TokenClientFactory {
    private final Map<String, OAuth2TokenClient> clientMap;

    @Autowired
    public OAuth2TokenClientFactory(List<OAuth2TokenClient> clients) {
        this.clientMap = clients.stream()
                .collect(Collectors.toMap(
                        c -> {
                            String name = c.getClass().getAnnotation(Component.class).value();
                            return name.replace("TokenClient", "");
                        },
                        c -> c
                ));
    }

    public OAuth2TokenClient getClient(String provider) {
        return clientMap.get(provider);
    }
}
