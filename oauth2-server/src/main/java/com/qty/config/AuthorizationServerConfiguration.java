package com.qty.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
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

import javax.annotation.Resource;

/**
 * 授权服务器的配置类
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

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
                .secret(passwordEncoder.encode("secret"))//客户端的密钥
                .authorizedGrantTypes("authorization_code","password","refresh_token")//授权类型
                .scopes("pc")//允许授权的范围
                .redirectUris("http://baidu.com");//回调地址
    }


    /**
     * 令牌的设置（管理服务）
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


    //设置授权码模式的授权码如何存取，暂时采用内存方式
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(){
        return new InMemoryAuthorizationCodeServices();
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
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);//允许post请求
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
}
