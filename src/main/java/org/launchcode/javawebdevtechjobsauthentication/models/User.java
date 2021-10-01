package org.launchcode.javawebdevtechjobsauthentication.models;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.Entity;
import javax.validation.constraints.NotNull;

@Entity
public class User extends AbstractEntity {

    @NotNull
    private String username;

    @NotNull
    private String hashedPassword;

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public User() {}

    public User(String username, String password) {
        this.username = username;
        this.hashedPassword = encoder.encode(password);
    }

    public String getUsername() {
        return username;
    }

    public boolean isMatchingPassowrd(String password) {
        return encoder.matches(password, hashedPassword);
    }
}
