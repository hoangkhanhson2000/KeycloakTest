package com.example.keycloaktest.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class BearerTokenFilter extends OncePerRequestFilter {

    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public BearerTokenFilter(JwtAuthenticationProvider jwtAuthenticationProvider) {
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication = jwtAuthenticationProvider.authenticate(authentication);


        SecurityContextHolder.clearContext();
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        log.info("Bearer filter: {}", authentication);

//        if (SecurityContextHolder.getContext().getAuthentication() != null &&
//                SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken) {
//            Jwt token = ((JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getToken();
//            List<GrantedAuthority> authorities = new ArrayList<>();
//
//
//            ((JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getAuthorities()
//                    .forEach(ga -> authorities.add(ga));
//            Jwt newToken = new Jwt(token.getTokenValue(),
//                    (Instant) token.getClaims().get("iat"),
//                    (Instant) token.getClaims().get("exp"),
//                    token.getHeaders(), token.getClaims());
//            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(newToken, authorities);
//            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);
//        }

        //filterChain.doFilter(request, response);

    }

}

