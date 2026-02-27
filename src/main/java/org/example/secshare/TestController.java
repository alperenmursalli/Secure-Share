package org.example.secshare;

import org.example.secshare.auth.security.UserPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal UserPrincipal user) {
        return "Hello " + user.email();
    }
}