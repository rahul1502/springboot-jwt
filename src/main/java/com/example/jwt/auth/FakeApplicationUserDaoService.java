package com.example.jwt.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // This method should have the code to fetch the user details from the DB
    @Override
    public Optional<User> selectApplicationUserByUsername(String username) {

        return getApplicationUsers().stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }


    // This is a dummy method to avoid the setup of a real DB
    private List<User> getApplicationUsers() {

        List<User> applicationUsers = new ArrayList<>() {{
            add(new User("rvala", passwordEncoder.encode("password"), new ArrayList<>()));
            add(new User("batman", passwordEncoder.encode("admin123"),  new ArrayList<>()));
            add(new User("robin", passwordEncoder.encode("admin123"),  new ArrayList<>()));
        }};

        return applicationUsers;
    }
}
