package com.qty.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.annotation.Resource;

/**
 * 授权服务器的配置类
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {



    @Autowired
    private TokenStore tokenStore;

    //令牌的管理服务
    @Autowired
    private ClientDetailsService clientDetailsService;
    //密码模式所需要
    @Autowired
    private AuthenticationManager authenticationManager;
    //授权码模式所需要
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    /**
     * 1、暴露出去哪些客户端以及客户端的保存方式（信息在内存中还是数据库中）
     * 配置客户端详情服务，客户端详情信息在这里初始化，将客户端的详情信息写死在这里或者通过数据库调取
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //客户端配置(授权码模式存在内存中，比较客户端id )
        clients.inMemory()
                .withClient("client")//客户端的id
                .secret(passwordEncoder().encode("secret"))//客户端的密钥
                .resourceIds("RESOURCE")//允许访问的资源ID
                .authorizedGrantTypes("authorization_code","password","refresh_token")//授权类型
                .scopes("pc")//允许授权的范围
                .redirectUris("http://baidu.com");//回调地址
    }

    /**
     * 2、令牌如何存取如何管理
     * 配置令牌的访问端点以及令牌的服务（1、内存方式 2、数据库方式 3、jwt方式）
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)//密码模式需要
                .authorizationCodeServices(authorizationCodeServices)//授权码模式需要
                .tokenServices(tokenServices())//令牌管里服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST,HttpMethod.GET);//允许post以及GET请求
    }

    /**
     *3、配置上安全约束(不用登录就可以访问)
     * 授权服务的安全配置（不是所有请求都能进来）
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")///oauth/token_key公开出去
                .checkTokenAccess("permitAll()")///oauth2/check_token公开出去
                .allowFormAuthenticationForClients();//表单认证
    }


    /**
     * 密码加密方式
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 授权码模式的存取策略——内存
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(){
        return new InMemoryAuthorizationCodeServices();
    }

    /**
     * 设置令牌的存储策略以及令牌的有效时间
     * @return
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices(){
        DefaultTokenServices services=new DefaultTokenServices();
        services.setClientDetailsService(clientDetailsService);//客户端信息服务
        services.setSupportRefreshToken(true);//是否刷新令牌
        services.setTokenStore(tokenStore);//令牌的存储策略
        services.setAccessTokenValiditySeconds(7200);//令牌的有效期2小时
        services.setRefreshTokenValiditySeconds(259200);//刷新令牌的有效期3天
        return services;
    }


    /**
     * 密码模式的认证配置
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager authenticationManager=new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                return daoAuhthenticationProvider().authenticate(authentication);
            }
        };
        return authenticationManager;
    }


    @Bean
    public AuthenticationProvider daoAuhthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        daoAuthenticationProvider.setHideUserNotFoundExceptions(false);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    /**
     *添加用户信息，暂读内存
     * @return
     */
    @Bean
    UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
        userDetailsService.createUser(User.withUsername("admin").password(passwordEncoder().encode("admin"))
                .authorities("ROLE_ADMIN").build());
        userDetailsService.createUser(User.withUsername("user").password(passwordEncoder().encode("user"))
                .authorities("ROLE_USER").build());
        return userDetailsService;
    }


}
