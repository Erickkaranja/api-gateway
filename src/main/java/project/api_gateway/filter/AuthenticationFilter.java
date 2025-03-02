package project.api_gateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import project.api_gateway.Feign.TokenValidator;

public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
    @Autowired
    private RouteValidator routeValidator;
    @Autowired
    private TokenValidator tokenValidator;

    public AuthenticationFilter(){
        super(Config.class);
    }
    @Override
    public GatewayFilter apply(Config config){
        return ((exchange, chain)-> {
            if (routeValidator.isSecure.test(exchange.getRequest())){
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                    throw new RuntimeException("missing AUTHORIZATION header!!");
                }
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader !=null && authHeader.startsWith("Bearer ")){
                    authHeader =  authHeader.substring(7);
                }
                try {
                    tokenValidator.validateToken(authHeader);
                } catch (Exception e) {
                    throw new RuntimeException("Invalid authorization key!!");
                }
            }
            return chain.filter(exchange);
        });
    }
    public static class Config{
    }
}
