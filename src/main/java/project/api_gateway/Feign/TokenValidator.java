package project.api_gateway.Feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient("AUTH_SERVICE")
public interface TokenValidator {
    @GetMapping("/validate_token")
    public boolean validateToken(@RequestParam("token") String token);
}
