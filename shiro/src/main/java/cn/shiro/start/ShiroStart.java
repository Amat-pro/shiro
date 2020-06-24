package cn.shiro.start;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages= {"cn.shiro"})
public class ShiroStart {
	public static void main(String[] args) {
		SpringApplication.run(ShiroStart.class,args);
	}
}
