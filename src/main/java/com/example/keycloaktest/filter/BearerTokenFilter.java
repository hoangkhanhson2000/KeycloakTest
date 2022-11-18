package com.example.keycloaktest.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j

public class BearerTokenFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");


//        String token = null;
//
//        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
//            token = authorizationHeader.substring(7);
//
//        }
        // Set authen (Get token -> parse token -> )

        CustomAuthentication authentication = new CustomAuthentication();
        authentication.setUserDetails(new CustomUserDetail());
        //

        SecurityContextHolder.clearContext();
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);


        //filterChain.doFilter(request, response);

    }

}
