package project.api_gateway.Config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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
    private UserDetailsService userDetailsService;

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
            //simple logs
            boolean x = jwtTokenHelper.validateToken(token);
            System.out.println(x);
            String userEmail = jwtTokenHelper.extractUsername(token);
            System.out.println(userEmail);

            if (jwtTokenHelper.validateToken(token) && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                SecurityContext securityContext = new SecurityContextImpl(authToken);

                return ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)).then();

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