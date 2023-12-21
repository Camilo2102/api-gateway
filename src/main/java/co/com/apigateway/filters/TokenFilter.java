package co.com.apigateway.filters;

import co.com.apigateway.models.TokenValidationModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;


@Component
public class TokenFilter extends AbstractGatewayFilterFactory<Object>{

    private final WebClient.Builder webClientBuilder;
    private WebClient webClient;

    @Value("${authentication.endpoint}")
    private String authEndpoint;

    public TokenFilter(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @PostConstruct
    private void init(){
        this.webClient = webClientBuilder.baseUrl(authEndpoint).build();
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                return webClient.get()
                        .uri("/api/auth/validateToken")
                        .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                        .retrieve()
                        .bodyToMono(TokenValidationModel.class)
                        .flatMap(response -> {
                            if (response.isStatus()) {
                                return chain.filter(exchange);
                            } else {
                               return handleRejectResponse(exchange, response);
                            }
                        });
            } else {
                TokenValidationModel tokenStatus = new TokenValidationModel(false, "No token provided");
                return handleRejectResponse(exchange, tokenStatus);
            }
        };
    }

    private Mono<Void> handleRejectResponse(ServerWebExchange exchange,TokenValidationModel tokenStatus){
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory()
                .wrap(tokenStatus.toString().getBytes(StandardCharsets.UTF_8))));
    }

}
