package project.api_gateway.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import project.api_gateway.Feign.TokenValidator;

@Service
public class TokenValidatorService {
    @Autowired
    private TokenValidator tokenValidator;

    public boolean validateToken(String token) {
        return tokenValidator.validateToken(token);
    }
}
