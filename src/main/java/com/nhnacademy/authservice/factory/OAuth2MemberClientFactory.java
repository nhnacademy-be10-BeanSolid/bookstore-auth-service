package com.nhnacademy.authservice.factory;

import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
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
        return clientMap.get(provider);
    }
}
