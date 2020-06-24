package cn.shiro.Realm;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class ShiroRealm extends AuthorizingRealm {

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		// TODO Auto-generated method stub
		
		System.out.println("ShiroRealm的doGetAuthenticationInfo(PrincipalCollection principalColllection)执行...");
		
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		
		//通过principalCollection获得用户提交的信息  PrincipalCollection封装的是用户的身份信息(包括通过的身份与通过身份的Realm名称等)
		String username = (String) principalCollection.getPrimaryPrincipal();
		//可以根据用户的身份信息到数据库查询权限信息
		
		/**
		Set<String> roleSet = new HashSet<>();
		Set<String> permissionSet = new HashSet<>();
		
		authorizationInfo.addRoles(roleSet);
		authorizationInfo.addStringPermissions(permissionSet);  **/
		
		authorizationInfo.addRole("role");
		authorizationInfo.addStringPermission("permission");
		
		return authorizationInfo;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// TODO Auto-generated method stub
		
		System.out.println("ShiroRealm的doGetAuthenticationInfo(AuthenticationToken token)方法执行...");
		
		//模拟数据库查询得到数据
		String username = "123";
		String password = "123";
		
		//进行自定义验证的过程
		/**
		 //判断账号是否存在
        if (user == null) {
            throw new UnknownAccountException();
        }
        //判断账号是否被冻结
        if (user.getState()==null||user.getState().equals("PROHIBIT")){
            throw new LockedAccountException();
            //密码错误异常 new IncorrectCredentialsException();
        }
        **/
		/**
		//通过token获得用户提交的信息  token.getCredentials可能是默认加密过的密码！！！
		String pass = (String) token.getCredentials();
		System.out.println("String pass = (String) token.getCredentials(); 执行结果 pass = " + pass);
		if(!password.equals(pass)) {
			throw new IncorrectCredentialsException();
		} **/
			
		System.out.println("token.getCredentials() = " + token.getCredentials());  
		System.out.println("token.getPrincipal() = " + token.getPrincipal());
		//可以在此处执行Session和缓存管理，比如清空该用户此次的会话信息和缓存信息(在进入Realm之前应该已经为用户设置了会话和缓存信息)
		
		return new SimpleAuthenticationInfo(username,password,null,getName());   //返回成功则说明自定义的登录验证成功，
		                                                                        //返回Info信息将交由authenticator进行验证
		                                                                        //参数:name password salt realmName
	}	
}