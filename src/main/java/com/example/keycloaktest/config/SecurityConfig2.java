package com.example.keycloaktest.config;

import com.example.keycloaktest.filter.BearerTokenFilter;
import com.example.keycloaktest.filter.JwtAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;



@Configuration
@EnableWebSecurity
class SecurityConfig2
        extends KeycloakWebSecurityConfigurerAdapter {

    private static final String[] WHITELIST_URLS = {
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/actuator/**",
    };
    public KeycloakClientRequestFactory keycloakClientRequestFactory;

    private final KeycloakLogoutHandler keycloakLogoutHandler;

    SecurityConfig2(KeycloakLogoutHandler keycloakLogoutHandler) {
        this.keycloakLogoutHandler = keycloakLogoutHandler;
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) {
        KeycloakAuthenticationProvider authenticationProvider = new KeycloakAuthenticationProvider();
        authenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(authenticationProvider);
    }


    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy(); //for bearer-only services
    }

    @Bean
    protected SessionRegistry buildSessionRegistry() {
        return new SessionRegistryImpl();
    }



    @Bean
//    @Override
    @ConditionalOnMissingBean(HttpSessionManager.class)
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }

    //    @Bean
//    @Autowired
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        JwtAuthenticationProvider JwtAuthenticationProvider = new JwtAuthenticationProvider();
        http
                .cors()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
//
//
                .addFilterAfter(new BearerTokenFilter(JwtAuthenticationProvider), LogoutFilter.class)
//
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .authorizeRequests()
                .antMatchers("/employee/{employeeId}").hasRole("user")
                .antMatchers("/employee", "/employee/").hasRole("admin")
                .antMatchers(WHITELIST_URLS).permitAll()
                .anyRequest().authenticated();
        http.oauth2Login()
                .and()
                .logout()
                .addLogoutHandler(keycloakLogoutHandler)
                .logoutSuccessUrl("/");
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
////                .anonymous().disable()
//                .cors()
//                .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
//                .and()
////                .addFilter(new BearerTokenFilter())
////
////////
//                .authorizeRequests()
//                .antMatchers("/employee/{employeeId}").hasRole("user")
//                .antMatchers("/employee", "/employee/").hasRole("admin")
//                .anyRequest().permitAll();
//        //                .and()
////                .addFilterBefore(new BearerTokenFilter(), BearerTokenFilter.class)
////                .addFilterAfter(new BearerTokenFilter(), BearerTokenFilter.class);
//
////        http.oauth2Login()
////                .and()
////                .logout()
////                .addLogoutHandler(keycloakLogoutHandler)
////                .logoutSuccessUrl("/");
//        return http.build();
//    }


}
