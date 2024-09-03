package com.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/board")
public class SecController {

    @GetMapping("")
    @ResponseBody
    public String index(Model model) {
        return "Spring Security Index";
    }

    @GetMapping("/loginForm")
    public String loginForm(@RequestParam(value = "error",required = false) String err,@RequestParam(value = "logout",required = false) String log, Model model) {

        if(err != null) {
            if(err.equals("T")) {
                model.addAttribute("error", "아이디나 암호가 틀렸습니다");
            }
        }
        else if(log != null) {
            if(log.equals("T")) {
                model.addAttribute("logout","로그아웃 성공");
            }
        }
        return "th/loginForm";
    }

    @GetMapping("/menu")
    public String menu(Model model){
        return "th/menu";
    }

    @GetMapping("/denied")
    public String denied(Model model){
        return "th/denied";
    }
    
    @GetMapping("/hello")
    @ResponseBody
    public String hello(){
        return "여기는 Hello World 입니다";
    }
}

