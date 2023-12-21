package co.com.apigateway.controllers;

import co.com.apigateway.filters.TokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class GateWayController {

    @Value("${authentication.endpoint}")
    private String authEndpoint;

    @Value("${files.endpoint}")
    private String filesEndpoint;
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder, TokenFilter tokenFilter) {
        return builder
                .routes()
                .route("auth_route", r -> r.path("/auth/**")
                        .filters(f -> f.rewritePath("/(?<segment>.*)", "/api/${segment}"))
                        .uri(authEndpoint))
                .route("file_route", r -> r.path("/files/**")
                        .filters(f -> f.rewritePath("/files/(?<segment>.*)", "/api/${segment}")
                                .filter(tokenFilter.apply(new Object())))
                        .uri(filesEndpoint))
                .build();
    }

    @Bean
    RedisRateLimiter redisRateLimiter() {
        return new RedisRateLimiter(1, 2);
    }


    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) throws Exception {
        return http.httpBasic().and()
                .csrf().disable()
                .authorizeExchange()
                .pathMatchers("/anything/**").authenticated()
                .anyExchange().permitAll()
                .and()
                .build();
    }

    @Bean
    public MapReactiveUserDetailsService reactiveUserDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
        return new MapReactiveUserDetailsService(user);
    }
}
