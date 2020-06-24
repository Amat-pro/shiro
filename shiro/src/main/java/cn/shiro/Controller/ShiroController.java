package cn.shiro.Controller;

import java.io.File;
import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

@Controller
public class ShiroController {

	//登录验证
	@RequestMapping("/FormAuthc")
	public void FormAuthc(HttpServletRequest request,HttpServletResponse responde) {
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(username,password);
		//token.setRememberMe(false);
		token.setRememberMe(true);
		try {
			subject.login(token);
		} catch(AuthenticationException e) {
			System.out.println("身份验证失败...");
		}
	}
	
	//  /successful 返回successful.html
	@RequestMapping("/successful") 
	public void Successful(HttpServletRequest request,HttpServletResponse response) {
		try {
			response.sendRedirect("successful.html");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//  /user 返回user.html
	@RequestMapping("/user") 
	public void User(HttpServletRequest request,HttpServletResponse response) {
		try {
			response.sendRedirect("user.html");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//  /authc 返回authc.html
	@RequestMapping("/authc") 
	public void Authc(HttpServletRequest request,HttpServletResponse response) {
		try {
			response.sendRedirect("authc.html");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//  /Role 打印subject是否有"role"角色
	@RequestMapping("/Role")
	public void Role(HttpServletRequest request,HttpServletResponse response) {
		Subject subject = SecurityUtils.getSubject();
		subject.checkRole("role");
		boolean hasRole = subject.hasRole("role");
		System.out.println("hasRole = " + hasRole);
	}
	
//  /Permission 打印subject是否有"permission"权限
	@RequestMapping("/Permission")
	public void Permission(HttpServletRequest request,HttpServletResponse response) throws IOException {
		Subject subject = SecurityUtils.getSubject();
		//subject.checkPermission("PERMISSION");     //会抛出异常的方法    //默认是忽略大小写的!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		boolean isPermitted = subject.isPermitted("permission");
		System.out.println("isPermitted = " + isPermitted);
		response.sendRedirect("successful.html");
	}
	
//	/testRoleFilter   打印map.put("/testRoleFilter","roles[role]") success True or False
	@RequestMapping("/testRoleFilter")
	public void testRoleFilter(HttpServletRequest request,HttpServletResponse response) throws IOException {
		Subject subject = SecurityUtils.getSubject();
		System.out.println("map.put(\"/testRoleFilter\",\"roles[role]\") success!");
		response.sendRedirect("successful.html");
	}

	//处理非application/x-www-form-urlencoded  比如multipart/form-data或application/json
	@RequestMapping("/json") 
	public void json(@RequestBody String name,@RequestBody String password) {
		//do something
	}
	//处理File和表单数据共同上传
	@RequestMapping("/fileAnddata")
	public void fileAnddata(HttpServletRequest request,HttpServletResponse responde) {
		MultipartHttpServletRequest Mrequest = (MultipartHttpServletRequest) request;
		//Mrequest.getParameter(name);
		//MultipartFile file = Mrequest.getFile(name);
	}
	
}





















