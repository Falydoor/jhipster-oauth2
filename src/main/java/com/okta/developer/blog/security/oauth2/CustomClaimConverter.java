package com.okta.developer.blog.security.oauth2;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collections;
import java.util.Map;

public class CustomClaimConverter implements Converter<Map<String, Object>, Map<String, Object>> {
    private final Logger log = LoggerFactory.getLogger(CustomClaimConverter.class);

    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    private final RestTemplate restTemplate;

    public CustomClaimConverter() {
        this.restTemplate = new RestTemplate();
    }

    public Map<String, Object> convert(Map<String, Object> claims) {
        Map<String, Object> convertedClaims = this.delegate.convert(claims);
        if (RequestContextHolder.getRequestAttributes() != null) {
            // Retrieve and set the token
            String token = bearerTokenResolver.resolve(((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
            HttpHeaders headers = new HttpHeaders() {{
                set("Authorization", "Bearer " + token);
            }};

            // Retrieve user infos from OAuth provider
            String path = (convertedClaims.get("iss").toString().contains("okta")) ? "/v1/userinfo" : "/protocol/openid-connect/userinfo";
            ResponseEntity<ObjectNode> userInfo = restTemplate.exchange(convertedClaims.get("iss") + path, HttpMethod.GET, new HttpEntity<String>(headers), ObjectNode.class);
            log.debug("USER INFO -> " + userInfo.getBody());

            // Custom claims are added
            convertedClaims.put("preferred_username", userInfo.getBody().get("preferred_username").asText());
        }
        return convertedClaims;
    }
}
