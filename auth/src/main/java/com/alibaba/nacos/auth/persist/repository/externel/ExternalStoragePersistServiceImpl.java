package com.alibaba.nacos.auth.persist.repository.externel;

import com.alibaba.nacos.auth.configuration.ConditionOnExternalStorage;
import com.alibaba.nacos.auth.persist.datasource.DataSourceService;
import com.alibaba.nacos.auth.persist.datasource.DynamicDataSource;
import com.alibaba.nacos.auth.persist.repository.PaginationHelper;
import org.springframework.context.annotation.Conditional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@SuppressWarnings(value = {"PMD.MethodReturnWrapperTypeRule", "checkstyle:linelength"})
@Conditional(value = ConditionOnExternalStorage.class)
@Component
public class ExternalStoragePersistServiceImpl {
    
    private DataSourceService dataSourceService;
    
    protected JdbcTemplate jt;
    
    /**
     * init datasource.
     */
    @PostConstruct
    public void init() {
        dataSourceService = DynamicDataSource.getInstance().getDataSource();
        
        jt = getJdbcTemplate();
    }
    
    /**
     * For unit testing.
     */
    public JdbcTemplate getJdbcTemplate() {
        return this.dataSourceService.getJdbcTemplate();
    }
    
    public <E> PaginationHelper<E> createPaginationHelper() {
        return new ExternalStoragePaginationHelperImpl<E>(jt);
    }
}




