package project.api_gateway;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class User implements UserDetails {

    private String userId;
    private String email;
    private String role;
    private String password; // Assuming password exists for the user

    // Additional fields as needed, e.g., for account status
    private boolean isAccountNonExpired;
    private boolean isAccountNonLocked;
    private boolean isCredentialsNonExpired;
    private boolean isEnabled;

    // Builder pattern for creating instances of User
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String userId;
        private String email;
        private String role;
        private String password;

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder role(String role) {
            this.role = role;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public User build() {
            User user = new User();
            user.userId = this.userId;
            user.email = this.email;
            user.role = this.role;
            user.password = this.password;
            user.isAccountNonExpired = true; // default value
            user.isAccountNonLocked = true;  // default value
            user.isCredentialsNonExpired = true; // default value
            user.isEnabled = true; // default value
            return user;
        }
    }

    // Implementing UserDetails methods

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // You may have more than one role/authority. Here we're creating a SimpleGrantedAuthority based on role
        return List.of(new SimpleGrantedAuthority("ROLE_" + this.role));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email; // You can also use userId if preferred
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    // Getters for custom fields
    public String getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getRole() {
        return role;
    }
}
