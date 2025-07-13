package com.understanding.spring.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@RestController
public class DemoController {
    private Logger logger = LoggerFactory.getLogger(getClass());

    public static List<Todo> TODO_LIST =new ArrayList<>(List.of(new Todo("vihanga", "Vihangaaaaa"),
            new Todo("malinda", "malindaaaaa")
    ));

    @GetMapping("/demo")
    public String getStringVal(){
        return  "Vihanga";
    }

    @GetMapping("/todos")
    public List<Todo> retrieveTodos(){
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveTodosForSpecificUser(@PathVariable String username){
        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createForSpecificUser(@PathVariable String username, @RequestBody Todo todo){
        TODO_LIST.add(todo);
        logger.info("Added todo");
    }

    @GetMapping("/csrf-token")
    public CsrfToken csrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }
}

record Todo (String username,String description){ }
