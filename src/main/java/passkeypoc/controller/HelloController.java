package passkeypoc.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {


//    @GetMapping("/")
//    public String hello(HttpSession session) {
//
//        session.setAttribute("foo", "bar");
//
//        return "Hello World!";
//    }

    @GetMapping("/get-session")
    public String getSession(HttpSession session) {

        String foo = (String) session.getAttribute("foo");
        System.out.println("foo: " + foo);

        session.setAttribute("zig", "zag");

        return "Hello World!";
    }

}
