package app.zinu.spring_security.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GetController {

    @GetMapping("/hello")
    public String GetHello() {
        return "Hello";
    }

}