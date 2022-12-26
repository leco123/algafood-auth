package com.algaworks.algafood.auth.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtKeyStoreProperties jwtKeyStoreProperties;

//    @Autowired
//    private RedisConnectionFactory redisConnectionFactory;

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
                    .authorizedGrantTypes("password","refresh_token")
                    // Tipos de escopo
                    .scopes("write","read")
                    //.accessTokenValiditySeconds(60 * 60 * 6)
                    .accessTokenValiditySeconds(60 * 60 * 6) // 6 horas
                    .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias

                // Cliente para aplicação backend usando client_credentials para acessar resource server
                .and()
                    .withClient("foodanalytics")
                    .secret(passwordEncoder.encode("food123"))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("write","read")
                    // http:/auth.algafood.local:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=NG6541nsdHEj&redirect_uri= http://www.foodanalytics.local:8082&code_challenge=teste123&code_challenge_method=s256
                    .redirectUris("http://www.foodanalytics.local:8082")

                .and()
                    .withClient("webadmin")
                    .authorizedGrantTypes("implicit")
                    .scopes("write","read")
                    // http:/auth.algafood.local:8081/oauth/authorize?response_type=token&client_id=foodanalytics&state=NG6541nsdHEj&redirect_uri= http://aplicacao-cliente
                    .redirectUris("http://aplicacao-cliente")

                // Cliente para aplicação backend usando client_credentials para acessar resource server
                .and()
                    .withClient("faturamento")
                    .secret(passwordEncoder.encode("faturamento123"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("write","read")

                // usado apenas para o Resource Server, fazer chamada da URI de introspeção
                .and()
                    .withClient("checktoken")
                    .secret(passwordEncoder.encode("check123"));
    }

    @Override
    public void configure (AuthorizationServerSecurityConfigurer security) throws Exception {
        // define que para acessar ou checkar precisa estar autorizado
//        security.checkTokenAccess("isAuthenticated()");
        // Não precisa de autenticação para gerar token
        security.checkTokenAccess("permitAll()")
                // permitir todos os acessos no endpoint tokenkey
                .tokenKeyAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }

    /**
     * Esse método é usado apenas para o Fluxo password
     */
    @Override
    public void configure (AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        var enhancerChain = new TokenEnhancerChain();
        enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));

        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
//                .tokenStore(redisTokenStore()) usado com redis
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenEnhancer(enhancerChain)
                .approvalStore(approvalStore(endpoints.getTokenStore()))
				.tokenGranter(tokenGranter(endpoints));
    }

    private ApprovalStore approvalStore(TokenStore tokenStore) {
        var aprovalStore = new TokenApprovalStore();
        aprovalStore.setTokenStore(tokenStore);
        return aprovalStore;
    }

//    private TokenStore redisTokenStore() {
//        return new RedisTokenStore(redisConnectionFactory);
//    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        // Usando algoritimo HMAC
        var jwtAccessTokenConverter = new JwtAccessTokenConverter();
        // definindo chave secreta, também conhecida como HmacSHA256
        //jwtAccessTokenConverter.setSigningKey("algaworkssdfsdf878451548748454f5asdfasdas");

        var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
        var keyStorePass = jwtKeyStoreProperties.getPassword();
        var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
        // abrir arquivo jks
        var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
        var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);

        jwtAccessTokenConverter.setKeyPair(keyPair);

        return jwtAccessTokenConverter;
    }

	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());

		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

		return new CompositeTokenGranter(granters);
	}
}