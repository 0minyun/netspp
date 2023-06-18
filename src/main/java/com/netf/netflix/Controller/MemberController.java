package com.netf.netflix.Controller;

import com.netf.netflix.Dto.MemberFormDto;
import com.netf.netflix.Entity.Member;
import com.netf.netflix.Repository.MemberRepository;
import com.netf.netflix.Service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.net.URLEncoder;
import java.sql.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/members")
@Controller
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping(value="/new")
    public String memberForm(Model model){
        model.addAttribute("memberFormDto",new MemberFormDto());
        return "/register";
    }

    @PostMapping(value = "/new")
    @ResponseBody
    public ResponseEntity<?> newMember(@RequestBody MemberFormDto memberFormDto, BindingResult bindingResult, Model model){
        System.out.println(memberFormDto.toString());
//        if(bindingResult.hasErrors()){
//            return ResponseEntity.badRequest().body("error");
//        }
        try{
            Member member = Member.createMember(memberFormDto, passwordEncoder);
            memberService.saveMember(member);

        }catch (IllegalStateException e){
            model.addAttribute("errorMessage",e.getMessage());
            ResponseEntity.badRequest().body(e.getMessage());
        }
        Map<String, Object> response = new HashMap<>();
        response.put("message", "회원가입이 성공하였습니다 로그인 해주세요");
        response.put("code", 200);
        return ResponseEntity.ok(response);
    }


    @GetMapping(value ="/login")
    public String loginMember(){
        return "/login";
    }
    @GetMapping(value="/login/error")
    public String loginError(Model model){
        model.addAttribute("loginEroorMsg","아이디 또는 비밀번호 확인해주세요.");
        return "/login";
    }

    @PostMapping(value="/login")
    public String loginMember(@ModelAttribute("memberFormDto") MemberFormDto memberFormDto, BindingResult bindingResult, Model model, HttpSession session) {
        // 이메일과 비밀번호를 가져옴
        String email = memberFormDto.getEmail();
        String password = memberFormDto.getPassword();

        try {

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            // 인증 성공 시
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 세션에 사용자 정보 저장

            session.setAttribute("loggedInUser", email);
            return "redirect:/profile/profile"; // 로그인 후 이동할 페이지 설정
        } catch (AuthenticationException e) {
            // 인증 실패 시
            model.addAttribute("loginError", "아이디 또는 비밀번호가 잘못되었습니다.");
            return "/login";
        }
    }

    @GetMapping(value = "/find-id")
    public String findIdMain(){
        return "/find-id";
    }

    @PostMapping(value = "/find-email")
    public String findIdPost(Model model, @RequestParam("name") String name,
                             @RequestParam("phonenum") String phonenum){
        Member member = memberRepository.findByNameAndPhoneNumber(name, phonenum);
        if(member == null || member.getEmail() == null){
            model.addAttribute("message", "찾으시는 이메일이 없습니다. 이름과 전화번호를 확인해주세요.");
        } else {
            model.addAttribute("message", "찾으시는 아이디는: " + member.getEmail());
        }
        return "/find-id";
    }

    @GetMapping(value = "/find-pw")
    public String findPwMain(){
        return "/find-pw";
    }

    @PostMapping(value = "/find-pw")
    public String findPwPost(HttpSession session, @RequestParam("email") String email,
                             @RequestParam("phonenum") String phonenum, Model model) {
        Member member = memberRepository.findByEmailAndPhoneNumber(email, phonenum);
        if(member != null) {
            session.setAttribute("member", member);
            return "/set-pw";
        }else{
            model.addAttribute("Message", "회원정보 조회에 실패했습니다.");
            return "/find-pw";
        }
    }

    @PostMapping(value = "/set-pw")
    public String setPwPost(@RequestParam("password") String password, HttpSession session) {
        Member member = (Member) session.getAttribute("member");

        String encodedPassword = passwordEncoder.encode(password);
        member.setPassword(encodedPassword);

        memberService.changePassword(member, encodedPassword);

        return "/login";
    }




}
