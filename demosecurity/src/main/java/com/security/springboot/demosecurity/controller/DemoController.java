package com.security.springboot.demosecurity.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class DemoController {

    @GetMapping(value="/")
    public String showHome(){
        return "Home";
    }

    @GetMapping(value="/leaders")
    public String showLeaders(){
        return "leaders";
    }

    @GetMapping(value="/showFeedback")
    public String showFeedbacks(){
        return "show-feedbacks";
    }

    @GetMapping(value="/systems")
    public String showSystems(){
        return "systems";
    }

}
