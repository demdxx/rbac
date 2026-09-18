package rbac

import (
	"context"
	"reflect"
)

// ResourcePermission implementation for some specific object type
type ResourcePermission struct {
	SimplePermission
	resName     string
	resType     reflect.Type
	matchByName bool
}

// NewResourcePermission object with custom checker and base type
func NewResourcePermission(name string, resType any, options ...Option) (*ResourcePermission, error) {
	if err := validatePermissionName(name); err != nil {
		return nil, err
	}
	perm := &ResourcePermission{
		SimplePermission: SimplePermission{name: name},
		resName:          GetResName(resType),
		resType:          GetResType(resType),
	}
	if perm.resType == nil {
		return nil, ErrInvalidResouceType
	}
	for _, opt := range options {
		if err := opt(perm); err != nil {
			return nil, err
		}
	}
	return perm, nil
}

// MustNewResourcePermission with name and resource type
func MustNewResourcePermission(name string, resType any, options ...Option) *ResourcePermission {
	perm, err := NewResourcePermission(name, resType, options...)
	if err != nil {
		panic(err)
	}
	return perm
}

// Name returns permission name
func (perm *ResourcePermission) Name() string {
	return perm.resName + `.` + perm.name
}

// ResourceName returns resource name
func (perm *ResourcePermission) ResourceName() string {
	return perm.resName
}

// ResourceType returns resource type
func (perm *ResourcePermission) ResourceType() reflect.Type {
	return perm.resType
}

// CheckPermissions to accept to resource
func (perm *ResourcePermission) CheckPermissions(ctx context.Context, resource any, patterns ...string) bool {
	return perm.CheckedPermissions(ctx, resource, patterns...) != nil
}

// CheckedPermission returns child permission for resource which has been checked as allowed
func (perm *ResourcePermission) CheckedPermissions(ctx context.Context, resource any, patterns ...string) Permission {
	if perm == nil || len(patterns) == 0 || resource == nil {
		return nil
	}
	expanded := ExpandPermissionPatterns(resource, patterns...)
	if checkResourcePattern(perm.resName, perm.name, expanded...) &&
		perm.matchResource(resource) &&
		perm.callCallback(ctx, perm, resource, patterns...) {
		return perm
	}
	for _, p := range perm.permissions {
		if r := p.CheckedPermissions(ctx, resource, patterns...); r != nil {
			return r
		}
	}
	return nil
}

func (perm *ResourcePermission) matchResource(resource any) bool {
	if perm.matchByName {
		return perm.CheckResourceName(resource)
	}
	return perm.CheckType(resource)
}

// CheckResourceName reports whether resource shares this permission's RBAC resource name.
func (perm *ResourcePermission) CheckResourceName(resource any) bool {
	if perm == nil {
		return false
	}
	name := GetResName(resource)
	return name != `` && name == perm.resName
}

// CheckType of resource and target type
func (perm *ResourcePermission) CheckType(resource any) bool {
	return perm.resType == GetResType(resource)
}

// ChildPermissions returns list of child permissions
func (perm *ResourcePermission) ChildPermissions() []Permission {
	return perm.permissions
}

// Permission returns permission by name
func (perm *ResourcePermission) Permission(name string) Permission {
	if perm.name == name || perm.Name() == name {
		return perm
	}
	for _, p := range perm.permissions {
		if p.Name() == name {
			return p
		} else if child := p.Permission(name); child != nil {
			return child
		}
	}
	return nil
}

// Permissions returns list of permissions by pattern
func (perm *ResourcePermission) Permissions(patterns ...string) []Permission {
	if perm == nil || len(patterns) == 0 {
		return nil
	}
	var res []Permission
	if perm.MatchPermissionPattern(patterns...) {
		res = append(res, perm)
	}
	for _, p := range perm.permissions {
		res = append(res, p.Permissions(patterns...)...)
	}
	return uniquePermissions(res)
}

// HasPermission returns true if permission has permission
func (perm *ResourcePermission) HasPermission(patterns ...string) bool {
	return perm.MatchPermissionPattern(patterns...) || len(perm.Permissions(patterns...)) > 0
}

// MatchPermissionPattern returns true if permission matches any of the patterns
func (perm *ResourcePermission) MatchPermissionPattern(patterns ...string) bool {
	if perm == nil {
		return false
	}
	return checkPattern(perm.Name(), patterns...)
}

// Ext returns additional user data
func (perm *ResourcePermission) Ext() any {
	return perm.extData
}
