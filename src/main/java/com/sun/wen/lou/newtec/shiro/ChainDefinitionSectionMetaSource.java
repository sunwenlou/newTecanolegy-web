package com.sun.wen.lou.newtec.shiro;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.Ini.Section;
import org.springframework.beans.factory.FactoryBean;


/**
 * 根据数据库动态创建权限验证规则
 * @author liujiasong
 * @date 2014年12月15日
 * @time 上午9:28:33
 */
public class ChainDefinitionSectionMetaSource implements
		FactoryBean<Ini.Section> {

	
    /**
     * 默认premission字符串
     * sso:对应shiro配置文件中关联的过滤器，该过滤器必须可找到(存在)
     */
    public static final String PREMISSION_STRING="authc,perms[\"{0}\"]";
    
    private String filterChainDefinitions;
    
	private ISecurityUsersFinder securityUsersFinder;
	
	public void setSecurityUsersFinder(ISecurityUsersFinder securityUsersFinder) {
		this.securityUsersFinder = securityUsersFinder;
	}

	@Override
	public Section getObject() throws Exception {
        //获取所有Resource
        List<PurviewInfo> list = securityUsersFinder.getAllPurivewInfos();
        
        Ini ini = new Ini();
        //加载默认的url
        ini.load(filterChainDefinitions);
        Ini.Section section = ini.getSection(Ini.DEFAULT_SECTION_NAME);
        Iterator<PurviewInfo> ite = list.iterator();
        //循环Resource的url,逐个添加到section中。section就是filterChainDefinitionMap,
        //里面的键就是链接URL,值就是存在什么条件才能访问该链接
        while(ite.hasNext()){
        	PurviewInfo purviewInfo = ite.next();
            //如果不为空值添加到section中
            if(StringUtils.isNotEmpty(purviewInfo.getOptPath()) && StringUtils.isNotEmpty(purviewInfo.getOptSign())) {
                section.put(purviewInfo.getOptPath().toString(),  MessageFormat.format(PREMISSION_STRING,purviewInfo.getOptSign().toString()));
            }
        }
        section.put("/**", "authc");
        //section.put("/authcMethod/testMethod", MessageFormat.format(PREMISSION_STRING,"useTestMethod"));
        return section;
	}
	
    /**
     * 通过filterChainDefinitions对默认的url过滤定义
     * @param filterChainDefinitions 默认的url过滤定义
     */
    public void setFilterChainDefinitions(String filterChainDefinitions) {
        this.filterChainDefinitions = filterChainDefinitions;
    }
    
	@Override
	public Class<?> getObjectType() {
		return this.getClass();
	}

	@Override
	public boolean isSingleton() {
		return false;
	}

}
