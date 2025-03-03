package project.api_gateway.Config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtTokenHelper jwtTokenHelper;

    public JwtAuthenticationFilter(JwtTokenHelper jwtTokenHelper) {
        this.jwtTokenHelper = jwtTokenHelper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String AUTHORIZATION = "Authorization";
        String requestToken = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION);

        if (requestToken != null && requestToken.startsWith("Bearer ")) {
            String token = requestToken.substring(7);
            System.out.println(token);
            boolean x = jwtTokenHelper.validateToken(token);
            System.out.println(x);
            if (jwtTokenHelper.validateToken(token)) {
                String userEmail = jwtTokenHelper.extractUsername(token);
                LOGGER.info("Extracted username: {}", userEmail);

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = jwtTokenHelper.extractPayloadFromToken(token);

                    List<SimpleGrantedAuthority> authorities = userDetails.getAuthorities().stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getAuthority())).toList();

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, authorities
                    );

                    SecurityContext securityContext = new SecurityContextImpl(authenticationToken);
                    LOGGER.info("SecurityContext set for user: {}", userDetails.getUsername());

                    String role = authorities.stream()
                            .findFirst()  // Assuming only one role is assigned; adjust if necessary
                            .map(SimpleGrantedAuthority::getAuthority)
                            .orElse("ROLE_USER");

                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("role", role)
                            .build();

                    ServerWebExchange modifiedExchange = exchange.mutate()
                            .request(modifiedRequest)
                            .build();

                    // Continue the filter chain with security context setup
                    return chain.filter(modifiedExchange)
                            .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
                }
            } else {
                LOGGER.error("Invalid or expired token");
            }
        } else {
            LOGGER.error("Authorization header missing or does not start with 'Bearer '");
        }

        // Continue the chain without a security context if the token is invalid/missing
        return chain.filter(exchange);
    }
}
