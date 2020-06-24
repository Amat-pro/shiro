package cn.shiro.Configuration;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.SessionValidationScheduler;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

//DelegatingFilterProxy:Shiro代理Servlet容器Filter的代理(FilterChainResolver FilterChainManager FilterChain Filter)
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.server.WebFilter;

import cn.shiro.Realm.ShiroRealm;

@Configuration
public class ShiroConfig {
	
	//Realm
	@Bean
	public Realm realm() {
		Realm realm = new ShiroRealm();
		return realm;
	}
	
	//AuthenticatorStratege
	@Bean
	public AuthenticationStrategy atLeastOneSuccessfulStrategy() {
		return new AtLeastOneSuccessfulStrategy();
	}
	//Authenticator
	@Bean
	public ModularRealmAuthenticator authenticator(AuthenticationStrategy authenticationStrategy) {
		ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
		//authenticator.setAuthenticationStrategy(authenticationStrategy);
		return authenticator;
	}
	
	//PermissionReslver
	@Bean
	public PermissionResolver permissionResolver() {
		return new WildcardPermissionResolver();
	}
	
	//RolePermissionResolver             !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	@Bean
	public RolePermissionResolver rolePermissionResolver() {
		return null;
	}   // 需要自定义实现  不进行自定义实现也可以进行角色验证
	//Authorizer                          !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	@Bean
	public Authorizer authorizer(PermissionResolver permissionResolver) {
		ModularRealmAuthorizer authorizer = new ModularRealmAuthorizer();
		authorizer.setPermissionResolver(permissionResolver);
		//authorizer.setRolePermissionResolver(rolePermissionResolver);
		return authorizer;
	}
	
	//会话
	//缓存管理器  SessionManager通过SessionDAO持久化会话，通过缓存缓存在内存中保存会话
	@Bean
	public CacheManager cacheManager() {
		EhCacheManager cacheManager = new EhCacheManager();
		//设置配置信息
		//cacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
		cacheManager.setCacheManagerConfigFile("./src/main/resources/ehcache.xml");    //.当前目录表示src的父级目录
		return cacheManager;
	}
	//会话Id生成器 默认是使用JavaUuidSessionIdGenerator
	@Bean
	public SessionIdGenerator sessionIdGenerator() {
		return (SessionIdGenerator) new JavaUuidSessionIdGenerator();
	}
	//会话存储/持久化   Shiro提供的SessionDAO
	@Bean
	public SessionDAO sessionDao(CacheManager cacheManager,SessionIdGenerator sessionIdGenerator) {
		EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
		sessionDAO.setCacheManager(cacheManager);
		sessionDAO.setSessionIdGenerator(sessionIdGenerator);
		return sessionDAO;
	}
	//SessionManager
	@Bean
	public SessionManager sessionManager(CacheManager cacheManager,SessionDAO sessionDAO,SessionValidationScheduler sessionValidationScheduler) {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		//设置会话的全局过期时间
		sessionManager.setGlobalSessionTimeout(20000);
		sessionManager.setDeleteInvalidSessions(true);
		sessionManager.setSessionValidationSchedulerEnabled(true);
		sessionManager.setCacheManager(cacheManager);
		sessionManager.setSessionDAO(sessionDAO);
		//sessionManager.setSessionListeners(listeners);
		//sessionManager.setSessionFactory(sessionFactory);
		sessionManager.setSessionValidationScheduler(sessionValidationScheduler);
		
		return sessionManager;
	}	
	/**
	//使用Cookie的SessionManager
	@Bean
	public SessionManager sessionManager1() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		//设置会话的全局过期时间
		sessionManager.setGlobalSessionTimeout(1800000);
		return sessionManager;
	} **/
	
	//会话创建  默认使用SimpleSessionFactory 是SessionManager的属性之一
	
	//会话监听器  实现SessionListener接口 (用于在会话创建，过期，退出/会话过期时触发) 是SessionManager的属性之一
	/**
		public class MySessionListener1 implements SessionListener {
		    @Override
		    public void onStart(Session session) {//会话创建时触发
		        System.out.println("会话创建：" + session.getId());
		    }
		    @Override
		    public void onExpiration(Session session) {//会话过期时触发
		        System.out.println("会话过期：" + session.getId());
		    }
		    @Override
		    public void onStop(Session session) {//退出/会话过期时触发
		        System.out.println("会话停止：" + session.getId());
		    }  
		}
	 */
	 	
	//会话验证 会话验证调度器，用于定期验证会话是否过期并作出处理  
	//org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler(sessionManager的属性)
	@Bean
	public SessionValidationScheduler sessionValidationScheduler() {
		SessionValidationScheduler sessionValidationScheduler = new ExecutorServiceSessionValidationScheduler();
		//SessionValidationScheduler sessionValidationScheduler = new QuartzSessionValidationScheduler();
		return sessionValidationScheduler;
	}
	
	
	//RememberMe配置   
	/**    ！！！！！！！！！！！！！！！！！！  只提供一个客户端Cookie模板即可
	//SessionIdCookie      注意与与RememberMeCookie的注入区分!!!!!   SessionIdCookie：
	@Bean                    
	public SimpleCookie sessionCookie() {
		SimpleCookie simpleCookie = new SimpleCookie("sid");
		simpleCookie.setHttpOnly(true);
		simpleCookie.setMaxAge(-1);   //-1表示浏览器关闭时失效此Cookie
		return simpleCookie;
	} **/
	//RememberMeCookie   注意与与SessionCookie的注入区分!!!!!
	@Bean
	public SimpleCookie rememberMeCookie() {
		SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
		simpleCookie.setHttpOnly(true);
		simpleCookie.setMaxAge(180000);
		return simpleCookie;
	}
	//RememberMeManager 
	@Bean
	public CookieRememberMeManager cookieRememberMeManager(SimpleCookie rememberMeCookie) {
		CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
		//cookieRememberMeManager.setCipherService(cipherService); //加密 默认AES算法（cipherService是生成密钥的组件吧）
		//这里若是不指定密钥，则每次shiro重新启动就会使用不同的密钥，导致不能识别之前加密过的cookie(报错信息:org.apache.shiro.crypto.CryptoException: Unable to execute 'doFinal' with cipher instance [javax.crypto.Cipher@7c296645].)
		cookieRememberMeManager.setCipherKey(Base64.decode("6ZmI6I2j5Y+R5aSn5ZOlAA=="));
		cookieRememberMeManager.setCookie(rememberMeCookie);
		return cookieRememberMeManager;	
	}
	
	@Bean
	public SecurityManager sercurityManager(Realm realm,Authenticator authenticator,Authorizer authorizer,SessionManager sessionManager,CookieRememberMeManager cookieRememberMeManager,CacheManager cacheManager) {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setAuthenticator(authenticator);
		//System.out.println(authenticator);
		securityManager.setAuthorizer(authorizer);
		//System.out.println(realm);
		securityManager.setRealm(realm);   //Realm的设置必须在Authentication的设置之后
		securityManager.setCacheManager(cacheManager);
		securityManager.setSessionManager(sessionManager);
		securityManager.setRememberMeManager(cookieRememberMeManager);
		//securityManager.getRealms();   返回一个RealmSecurityManager对象，可用于设置AuthenticationInfo缓存等
		return securityManager;
	}

	/**   ！！！！此部分为DelegatingFilterProxy的配置，在Spring项目中应该需要进行配置，SpringBoot应该是采用了约定而不需要配置
	@Bean   
	public ContextLoaderListener getcontextLoaderListener() {
		return new ContextLoaderListener();
	} **/
	
	
	//filter
	/**
	//@Bean   //这样创建时会出现错误，应该是不允许
	public DelegatingFilterProxy delegatingFilterProxy() {
		DelegatingFilterProxy delegatingFilterProxy = new DelegatingFilterProxy();
		delegatingFilterProxy.setTargetBeanName("shiroFilter");   //增加这条语句，设置代理的Filter就可以成功注册DelegatingFilterProxy了!!!!!!!
		delegatingFilterProxy.setTargetFilterLifecycle(true);
		
		return delegatingFilterProxy;
	} **/
	//SpringBoot注册Filter   //注册多个Filter需要声明多个FilterRegistrationBean   自定义Bean可以使用@WebFilter
	@Bean
	public FilterRegistrationBean<Filter> ShiroFilter() {
		DelegatingFilterProxy delegatingFilterProxy = new DelegatingFilterProxy("shiroFilter");
		delegatingFilterProxy.setTargetFilterLifecycle(true);
		delegatingFilterProxy.setTargetBeanName("shiroFilter");   //增加这条语句，设置代理的Filter就可以成功注册DelegatingFilterProxy了!!!!!!!
		FilterRegistrationBean<Filter> filterRegistrationBean = new FilterRegistrationBean<>();
		filterRegistrationBean.setFilter(delegatingFilterProxy);
		filterRegistrationBean.addUrlPatterns("/*");
		filterRegistrationBean.setOrder(1);
		return filterRegistrationBean;
	}      //SpringBoot中应该是不需要配置DelegatingFilterProxy的（也许默认使用了这个Proxy Filter  
	         //只需要使用ShiroFilterFactoryBean就可以设置Filter即可[ShiroFilterFactory可能能够联系到这个Proxy Filter]）
	//不定义DelegatingFilterProxy也能够运行,应该是SpringBoot作了额外的注册工作,也就是使用了约定
	
	@Bean(name="shiroFilter")
	public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		Map<String,String> map = new HashMap<>();
		//Map<String,Filter> mapFilter = new HashMap<>();
		//mapFilter.put("formAuthenticationFilter",formAuthenticationFilter);
		/**
		map.put("/authc", "anon");
		map.put("/form","authc");
		map.put("", "user");
		map.put("url","formAuthenticationFilter");
		map.put("url","forceLogoutFilter");        //需要先注册
		**/
		map.put("/FormAuthc","anon");
		map.put("/authc","authc");
		map.put("/successful","anon");
		map.put("/user","user");                    
		//可以添加权限，角色拦截器！！！！！
		map.put("/testRoleFilter","roles[role]");
		shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
		shiroFilterFactoryBean.setLoginUrl("/login.html");
		shiroFilterFactoryBean.setSuccessUrl("/successful.html");   
		//RememberMeFilter
		//shiroFilterFactoryBean.setFilters(mapFilter);
		return shiroFilterFactoryBean;
	}
	
	//RememberMe的Filter  需要注册到FilterChain     //可以不使用这个拦截器，在Controller层进行操作时设置记住我为true即可
	@Bean
	public FormAuthenticationFilter shiroFilter() {
		FormAuthenticationFilter formAuthenticationFilter = new FormAuthenticationFilter();
		String rememberMeParam = "RememberMe";
		//设置表单提交的是否RememberMe的属性信息
		formAuthenticationFilter.setRememberMeParam(rememberMeParam);
		return formAuthenticationFilter;
	}
	
	/**  会话在线控制的Filter  需要在Chain上注册代名字的该Filter，并设置登录页面url使用该拦截器拦截处理
	 public class ForceLogoutFilter extends AccessControlFilter {
    	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        	Session session = getSubject(request, response).getSession(false);
        	if(session == null) {
            	return true;
        	}
        	return session.getAttribute(Constants.SESSION_FORCE_LOGOUT_KEY) == null;
    		}
    		protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        	try {
            	getSubject(request, response).logout();//强制退出
        	} catch (Exception e) {/*ignore exception*}
        	String loginUrl = getLoginUrl() + (getLoginUrl().contains("?") ? "&" : "?") + "forceLogout=1";
        	WebUtils.issueRedirect(request, response, loginUrl);
        	return false;
        }
    }
	**/

}


