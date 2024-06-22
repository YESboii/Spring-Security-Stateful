package com.example.Security;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ListeningSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;


@RestController
public class TestController {

    @Autowired
    AuthenticationManager authenticationManager;

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();



    @PostMapping("/login")
    public ResponseEntity<String> testLogin(@RequestBody Login login, HttpServletRequest request, HttpServletResponse response){
        System.out.println(login.toString());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(login.username(),login.password());

        Authentication authentication = authenticationManager.authenticate(token);
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();

        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication().getName());
    }
    @GetMapping("/login")
    public ResponseEntity<String> testLogin1(){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return ResponseEntity.ok(authentication.getName());
    }
    @GetMapping("/test")
    public ResponseEntity<String> testLogin2(){
        return ResponseEntity.ok("ellll2");
    }
}
