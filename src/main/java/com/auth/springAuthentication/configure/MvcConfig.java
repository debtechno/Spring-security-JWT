package com.auth.springAuthentication.configure;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@EnableWebMvc
@Configuration
public class MvcConfig extends WebMvcConfigurerAdapter {
	private String basPath = "C:/Users/WC939EQ/OneDrive - EY/Documents/My_Workspaces/SpringBootProjects/ex-fo-user-service/src/main/webapp";
    @Override
    public void addResourceHandlers(
      ResourceHandlerRegistry registry) {
 
        registry.addResourceHandler("/static/**")
          .addResourceLocations(basPath+"/WEB-INF/view/react/build/static/");
        registry.addResourceHandler("/*.js")
          .addResourceLocations(basPath+"/WEB-INF/view/react/build/");
        registry.addResourceHandler("/*.json")
          .addResourceLocations(basPath+"/WEB-INF/view/react/build/");
        registry.addResourceHandler("/*.ico")
          .addResourceLocations(basPath+"/WEB-INF/view/react/build/");
        registry.addResourceHandler("/index.html")
          .addResourceLocations(basPath+"/WEB-INF/view/react/build/index.html");
    }
}
