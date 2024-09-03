package com.web;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableWebSecurity
public class JdbcSecurityConfig
{
    @Autowired
    DataSource dataSource;    // JDBC Authentication에 필요함

    @Bean
    public BCryptPasswordEncoder  passwordEncoder() {
        BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
        log.info("smith->" + enc.encode("smith")); // ROLE_ADMIN
        log.info("blake->" + enc.encode("blake")); // ROLE_USER
        log.info("jones->" + enc.encode("jones")); // ROLE_GUEST
        return enc;
    }

    //Enable jdbc authentication
    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        log.info("데이터소스 설정");
        auth.jdbcAuthentication().dataSource(dataSource);

       /* users, authorities 이외의 다른 테이블 이름을 사용하는 경우에는 아래의 설정이 필수
       auth.jdbcAuthentication().dataSource(dataSource)
       .usersByUsernameQuery(
                "SELECT username,password, enabled FROM users WHERE username=?")
       .authoritiesByUsernameQuery(
                "SELECT username, authority FROM authorities WHERE username=?");
       */
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/resources/**", "/ignore2");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("접근제한 설정");
        http.authorizeHttpRequests(authz -> authz
                        .requestMatchers("/", "/board", "/board/loginForm", "/board/denied", "/logout").permitAll()
                        .requestMatchers("/board/input").hasAnyRole("USER", "ADMIN", "MASTER")
                        .requestMatchers("/board/list").hasAnyRole("GUEST","USER", "ADMIN","MASTER")
                        .requestMatchers("/board/add").hasAnyRole("USER", "ADMIN", "MASTER")
                        .requestMatchers("/board/detail/**").hasAnyRole("GUEST", "USER", "ADMIN","MASTER")
                        .requestMatchers("/board/edit/**, /board/update").hasAnyRole("USER")
                        .requestMatchers("/board/reply/**").hasAnyRole("ADMIN")
                        .requestMatchers("/board/del/**").hasAnyRole("MASTER")
                        //.anyRequest().authenticated()  // 위의 설정 이외의 모든 요청은 인증을 거쳐야 한다
                        .anyRequest().denyAll()        // 위의 설정 이외의 모든 요청은 거부한다
                //.anyRequest().permitAll()       // 위의 설정 이외의 모든 요청은 인증 요구하지 않음
        ).csrf( csrfConf -> csrfConf.disable()
        ).formLogin(loginConf -> loginConf.loginPage("/board/loginForm")   // 컨트롤러 메소드와 지정된 위치에 로그인 폼이 준비되어야 함
                .loginProcessingUrl("/doLogin")            // 컨트롤러 메소드 불필요, 폼 action과 일치해야 함
                .failureUrl("/board/loginForm?error=T")      // 로그인 실패시 이동 경로(컨트롤러 메소드 필요함)
                //.failureForwardUrl("/login?error=Y")  //실패시 다른 곳으로 forward
                .defaultSuccessUrl("/board", true)
                .usernameParameter("id")  // 로그인 폼에서 이용자 ID 필드 이름, 디폴트는 username
                .passwordParameter("pw")  // 로그인 폼에서 이용자 암호 필트 이름, 디폴트는 password
                .permitAll()
        ).logout(logoutConf -> logoutConf.logoutRequestMatcher(new AntPathRequestMatcher("/logout")) //로그아웃 요청시 URL
                .logoutSuccessUrl("/board/loginForm?logout=T")   // 로그아웃 성공시 다시 로그인폼으로 이동
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
        ).exceptionHandling(exConf -> exConf.accessDeniedPage("/board/denied")); // 권한이 없어 접속 거부할 때

        return http.build();
    }

    // 메모리 기반 인증을 위한 메소드 제거함
}