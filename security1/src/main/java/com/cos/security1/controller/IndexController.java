package com.cos.security1.controller;


import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@ResponseBody
	@GetMapping("/test/login")
	public String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails) {
		log.info("/test/login================================");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		log.info("authentication:{}", principalDetails.getUser());

		log.info("userDetails:{}", userDetails.getUser());

		return "세션 정보 확인";
	}

	@ResponseBody
	@GetMapping("/test/oauth/login")
	public String testOAuthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) {
		log.info("/test/oauth/login================================");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		log.info("authentication:{}", oauth2User.getAttributes());

		log.info("oauth2User:{}",oauth.getAttributes());
		return "세션 정보 확인";
	}
	
	//locallhost:8080/
	//locallhost:8080
	@GetMapping("/")
	public String index() {
		//머스테치 기본폴더 src/main/resources/
		//뷰리졸버 설정 : templates(prefix), .mustache(suffix)
		return "index";
	}

	// OAuth 로그인을 해도 PrincipalDetails
	// 일반 로그인을 해도 PrincipalDetails
	// 둘 다 받을 수 있다
	@ResponseBody
	@GetMapping("/user")
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {

		log.info("principalDetails={}", principalDetails.getUser());
		return "user";
	}
	
	@ResponseBody
	@GetMapping("/admin")
	public String admin() {
		return "admin";
	}
	
	@ResponseBody
	@GetMapping("/manager")
	public String manager() {
		return "manager";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		log.info(user.toString());
		user.setRole("ROLE_USER");

		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);

		user.setPassword(encPassword);
		userRepository.save(user); //회원가입 잘됨. but 비밀번호가 1234 -> 시큐리티로 로그인 할 수 없음. 패스워크 암호화가 안되었기 때문

		return "redirect:/loginForm";
	}

	@Secured("ROLE_ADMIN")
	@ResponseBody
	@GetMapping("/info")
	public String info() {
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@ResponseBody
	@GetMapping("/data")
	public String data() {
		return "데이터정보";
	}
}
