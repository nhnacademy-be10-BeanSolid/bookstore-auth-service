package com.nhnacademy.authservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "Auth-Service Swagger",
        description = "BeanSolid-BookStore의 인증에 관한 REST API",
        version = "1.0.0"
    )
)
public class OpenApiConfig {
}
