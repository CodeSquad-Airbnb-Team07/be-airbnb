package team07.airbnb.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import team07.airbnb.domain.user.enums.Role;
import team07.airbnb.domain.user.service.CustomOAuthUserService;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuthUserService oAuth2UserService;
    private final CustomSuccessHandler successHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(
                        (csrfConfig) -> csrfConfig.disable()
                )
                .headers(
                        (headerConfig) -> headerConfig.frameOptions(
                                frameOptionsConfig -> frameOptionsConfig.disable()
                        )
                )
                .authorizeHttpRequests((authorizeRequest) -> authorizeRequest
//                        .requestMatchers("/posts/new", "/comments/save").hasRole(Role.USER.name())
//                        .requestMatchers("/", "/css/**", "images/**", "/js/**", "/login/*", "/logout/*", "/posts/**", "/comments/**").permitAll()
//                        .anyRequest().permitAll()
//                        .requestMatchers("/review/**", "/payment/**", "/booking/**").authenticated()
                        .anyRequest().permitAll()
                )
                .logout(
                        (logoutConfig) -> logoutConfig.logoutSuccessUrl("/")
                )
                // OAuth2 로그인 기능에 대한 여러 설정
                // oauth2 로그인 추가
                .oauth2Login(
                        oAuth -> {
                            oAuth.userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService));
                            oAuth.successHandler(successHandler);
                        }
                );

        return http.build();
    }


//    @Bean
//    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(auth -> auth
//                .requestMatchers("/**").permitAll()
//                .requestMatchers("/admin/**").hasRole("ADMIN")
//        );
//        return http.build();
//    }
}
