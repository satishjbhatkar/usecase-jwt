package com.app.jwtsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
    @Autowired
    MyUserDetailService myUserDetailService;
    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;
    @GetMapping("/jwt")
    public String Data(){
        return "JWT Token";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken
            (@RequestBody AuthenticationRequest authenticationRequest) throws Exception{

        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(),
                            authenticationRequest.getPassword()));
        }catch (Exception e){
            throw new Exception("Incorrect user name and password",e);
        }

        final UserDetails userDetails= myUserDetailService.loadUserByUsername(authenticationRequest.getUserName());
        final String jwt=jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));

    }

}
