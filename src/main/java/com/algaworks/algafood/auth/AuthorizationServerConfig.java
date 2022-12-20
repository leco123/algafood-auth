package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * Define que determinado usuário usando password *** pode usar o fluxo: password
     */
    @Override
    public void configure (ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    // identificação do cliente
                    .withClient("algafood-web")
                    .secret(passwordEncoder.encode("web123"))
                    // São fluxos
                    .authorizedGrantTypes("password")
                    // Tipos de escopo
                    .scopes("write","read")
                    .accessTokenValiditySeconds(60 * 60 * 6)
                .and()
                    .withClient("algafood-mobile")
                    .secret(passwordEncoder.encode("abc555"))
                    .authorizedGrantTypes("password")
                    .scopes("write","read")
                    .accessTokenValiditySeconds(60 * 60 * 6);
    }

    /**
     * Esse método é usado apenas para o Fluxo password
     */
    @Override
    public void configure (AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager);
    }
}
