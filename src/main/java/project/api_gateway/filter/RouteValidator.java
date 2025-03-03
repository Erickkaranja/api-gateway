/**

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
import project.api_gateway.Config.JwtTokenHelper;
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

        String token = null;

        if (requestToken != null && requestToken.startsWith("Bearer")) {
            token = requestToken.substring(7);
            boolean x = jwtTokenHelper.validateToken(token);
            System.out.println(x);

            if (jwtTokenHelper.validateToken(token) && SecurityContextHolder.getContext().getAuthentication() == null) {
                /**
                 UserDetails user = jwtTokenHelper.extractPayloadFromToken(token);

                 List<SimpleGrantedAuthority> authorities = user.getAuthorities().stream()
                 .map((role) -> new SimpleGrantedAuthority("ROLE_" + role)).toList();

                 UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                 user, null, authorities);

                 SecurityContext context = new SecurityContextImpl(authenticationToken);

                 UserResponse principal = jwtTokenHelper
                 .extractPayloadFromToken((UserResponse) context.getAuthentication().getPrincipal());

                 // Set the Principal header in the request
                 ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                 .header("userId", principal.getUserId()) // Assuming username is appropriate for Principal
                 .header("email", principal.getEmail()) // Assuming username is appropriate for Principal
                 .header("role", principal.getRole()) // Assuming username is appropriate for Principal
                 .build();

                 // Create a new ServerWebExchange with the modified request
                 ServerWebExchange modifiedExchange = exchange.mutate()
                 .request(modifiedRequest)
                 .build();

                System.out.println(exchange.getRequest().getHeaders());
                return chain.filter(exchange);
            } else {
                LOGGER.error("TOKEN IS MALFORMED OR EXPIRED");
            }
        } else {
            LOGGER.error("TOKEN NOT FOUND");
        }
        return chain.filter(exchange);
    }

}
**/