package org.launchcode.javawebdevtechjobsauthentication.controllers;

import org.launchcode.javawebdevtechjobsauthentication.data.UserRepository;
import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.LoginFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.RegistrationFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    private UserRepository userRepository;

    private static final String sessionKey = "user";

    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(sessionKey);

        if (userId == null) {
            return null;
        }

        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }

        return user.get();
    }

    public static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(sessionKey, user.getId());
    }

    @GetMapping("register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegistrationFormDTO());
        model.addAttribute("title", "Register");
        return "register";
    }

    @PostMapping("register")
    public String processRegistrationForm(@ModelAttribute @Valid RegistrationFormDTO registrationFormDTO,
                                          Errors errors, HttpServletRequest request,
                                          Model model) {

        if (errors.hasErrors()) {
            displayRegistrationForm(model);
        }

        User existingUser = userRepository.findByUsername(registrationFormDTO.getUsername());

        if (existingUser != null) {
            errors.rejectValue("username", "username.alreadyexists",
                    "A user with that username already exists");
            displayRegistrationForm(model);
        }

        String password = registrationFormDTO.getPassword();
        String verifyPassword = registrationFormDTO.getVerifyPassword();

        if (!password.equals(verifyPassword)) {
            errors.rejectValue("password", "password.mismatch",
                    "Passwords do not match");
            displayRegistrationForm(model);
        }

        User newUser = new User(registrationFormDTO.getUsername(), password);

        userRepository.save(newUser);
        setUserInSession(request.getSession(), newUser);

        return "redirect:";
    }

    @GetMapping("login")
    public String displayLoginForm(Model model) {
        model.addAttribute(new LoginFormDTO());
        model.addAttribute("title", "Login");

        return "login";
    }

    @PostMapping("login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO,
                                   Errors errors, HttpServletRequest request,
                                   Model model) {

        if (errors.hasErrors()) {
            displayLoginForm(model);
        }

        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());

        if (theUser == null) {
            errors.rejectValue("username", "user.invalid", "The given username does not exist");
            displayLoginForm(model);
        }

        String password = loginFormDTO.getPassword();

        if (!theUser.isMatchingPassowrd(password)) {
            errors.rejectValue("password", "password.invalid", "Invalid password");
            displayLoginForm(model);
        }

        setUserInSession(request.getSession(), theUser);

        return "redirect:";
    }

    @GetMapping("logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "redirect:/login";
    }
}
