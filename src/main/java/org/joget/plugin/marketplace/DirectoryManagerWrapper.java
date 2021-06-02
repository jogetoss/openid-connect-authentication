package org.joget.plugin.marketplace;

import java.util.Collection;
import org.joget.directory.model.Department;
import org.joget.directory.model.Grade;
import org.joget.directory.model.Group;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;

public class DirectoryManagerWrapper implements DirectoryManager {
    
    DirectoryManager directoryManager;
    boolean bypassAuthentication;

    public DirectoryManagerWrapper(DirectoryManager dm, boolean bypassAuthentication) {
        this.directoryManager = dm;
        this.bypassAuthentication = bypassAuthentication;
    }
    
    @Override
    public boolean authenticate(String username, String password) {
        if (this.bypassAuthentication) {
            return true;
        } else {
            return directoryManager.authenticate(username, password);
        }
    }

    @Override
    public Group getGroupById(String groupId) {
        return directoryManager.getGroupById(groupId);
    }

    @Override
    public Group getGroupByName(String groupName) {
        return directoryManager.getGroupByName(groupName);
    }

    @Override
    public Collection<Group> getGroupByUsername(String username) {
        return directoryManager.getGroupByUsername(username);
    }

    @Override
    public Collection<Group> getGroupList() {
        return directoryManager.getGroupList();
    }

    @Override
    public Collection<Group> getGroupList(String nameFilter, String sort, Boolean desc, Integer start, Integer rows) {
        return directoryManager.getGroupList(nameFilter, sort, desc, start, rows);
    }

    @Override
    public Long getTotalGroups() {
        return directoryManager.getTotalGroups();
    }

    @Override
    public Collection<User> getUserByDepartmentId(String departmentId) {
        return directoryManager.getUserByDepartmentId(departmentId);
    }

    @Override
    public Collection<User> getUserByGradeId(String gradeId) {
        return directoryManager.getUserByGradeId(gradeId);
    }

    @Override
    public Collection<User> getUserByGroupId(String groupId) {
        return directoryManager.getUserByGroupId(groupId);
    }

    @Override
    public Collection<User> getUserByGroupName(String groupName) {
        return directoryManager.getUserByGroupName(groupName);
    }

    @Override
    public User getUserById(String userId) {
        return directoryManager.getUserById(userId);
    }

    @Override
    public Collection<User> getUserByOrganizationId(String organizationId) {
        return directoryManager.getUserByOrganizationId(organizationId);
    }

    @Override
    public User getUserByUsername(String username) {
        return directoryManager.getUserByUsername(username);
    }

    @Override
    public Collection<User> getUserList() {
        return directoryManager.getUserList();
    }

    @Override
    public Collection<User> getUserList(String nameFilter, String sort, Boolean desc, Integer start, Integer rows) {
        return directoryManager.getUserList(nameFilter, sort, desc, start, rows);
    }

    @Override
    public Long getTotalUsers() {
        return directoryManager.getTotalUsers();
    }

    @Override
    public boolean isUserInGroup(String username, String groupName) {
        return directoryManager.isUserInGroup(username, groupName);
    }

    @Override
    public Collection<Role> getUserRoles(String username) {
        return directoryManager.getUserRoles(username);
    }

    @Override
    public User getDepartmentHod(String departmentId) {
        return directoryManager.getDepartmentHod(departmentId);
    }

    @Override
    public Collection<User> getUserHod(String username) {
        return directoryManager.getUserHod(username);
    }

    @Override
    public Collection<User> getUserSubordinate(String username) {
        return directoryManager.getUserSubordinate(username);
    }

    @Override
    public Collection<User> getUserDepartmentUser(String username) {
        return directoryManager.getUserDepartmentUser(username);
    }

    @Override
    public Collection<User> getDepartmentUserByGradeId(String departmentId, String gradeId) {
        return directoryManager.getDepartmentUserByGradeId(departmentId, gradeId);
    }

    @Override
    public Department getDepartmentById(String departmentId) {
        return directoryManager.getDepartmentById(departmentId);
    }

    @Override
    public Collection<Department> getDepartmentList() {
        return directoryManager.getDepartmentList();
    }

    @Override
    public Collection<Department> getDepartmentList(String sort, Boolean desc, Integer start, Integer rows) {
        return directoryManager.getDepartmentList(sort, desc, start, rows);
    }

    @Override
    public Collection<Department> getDepartmentListByOrganization(String organizationId, String sort, Boolean desc, Integer start, Integer rows) {
        return directoryManager.getDepartmentListByOrganization(organizationId, sort, desc, start, rows);
    }

    @Override
    public Long getTotalDepartments(String organizationId) {
        return directoryManager.getTotalDepartments(organizationId);
    }

    @Override
    public Grade getGradeById(String gradeId) {
        return directoryManager.getGradeById(gradeId);
    }

    @Override
    public Collection<Grade> getGradeList() {
        return directoryManager.getGradeList();
    }
    
}
