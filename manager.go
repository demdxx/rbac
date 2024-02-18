// Package rbac provides role-based access control (RBAC) system
package rbac

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/demdxx/xtypes"
)

var ErrResourceTypeRequired = errors.New(`resource type required`)

const (
	OwnOwner   = `owner`   // The owner of the object (creator or user assigned as owner)
	OwnAccount = `account` // The account owner
	OwnAll     = `all`     // The system owner (can control all objects) *not recommended
)

var owningTypes = []string{OwnOwner, OwnAccount, OwnAll}

type objectItem struct {
	objType      any
	checkCallbac any
}

// Manager of the roles and permissions
//
// The manager is the main object of the system which contains all roles and permissions
// and provides methods to check permissions and roles for the object.
//
// Default manager implements implies that all permissions will be defined in the code.
//
// Default manager implements chain permission name type
//
//	Object permission name: `objectType.permissionName.owner|account|all`
//	where objectType is the object type name, permissionName is the permission name
//	and owner|account|all is the owner type
type Manager struct {
	mx sync.RWMutex

	roleAccessors RoleAccessors

	roles       map[string]Role
	permissions map[string]Permission

	// Object context data
	objects map[string]*objectItem
}

// NewManager creates new manager
func NewManager(roleAccessor RoleAccessors) *Manager {
	return &Manager{
		roleAccessors: roleAccessor,
		roles:         make(map[string]Role),
		permissions:   make(map[string]Permission),
		objects:       make(map[string]*objectItem),
	}
}

// NewManagerWithLoader creates new manager with role loader
func NewManagerWithLoader(roleLoader RoleLoader, lifetimeCache time.Duration) *Manager {
	return NewManager(newCachedRoleLoader(roleLoader, lifetimeCache))
}

// RegisterObject for processing
func (mng *Manager) RegisterObject(objType, checkCallbac any) *Manager {
	mng.objects[GetResName(objType)] = &objectItem{
		objType:      objType,
		checkCallbac: checkCallbac,
	}
	return mng
}

func (mng *Manager) objectItem(obj any) *objectItem {
	return mng.objects[GetResName(obj)]
}

// AddRole to the manager
func (mng *Manager) Role(ctx context.Context, name string) Role {
	mng.mx.RLock()
	defer mng.mx.RUnlock()
	if mng.roleAccessors != nil {
		if ro := mng.roleAccessors.Role(ctx, name); ro != nil {
			return mng.prepareRole(ctx, ro)
		}
	}
	return mng.roles[name]
}

// Role returns role by name
func (mng *Manager) Roles(ctx context.Context, names ...string) []Role {
	if len(names) > 0 {
		roles := make([]Role, 0, len(names))
		for _, name := range names {
			if role := mng.Role(ctx, name); role != nil {
				roles = append(roles, role)
			}
		}
		return roles
	}

	// Return all roles
	mng.mx.RLock()
	defer mng.mx.RUnlock()

	roles := make([]Role, 0, len(mng.roles))
	if mng.roleAccessors != nil {
		roles = append(roles,
			xtypes.Slice[Role](mng.roleAccessors.Roles(ctx)).Apply(
				func(role Role) Role { return mng.prepareRole(ctx, role) })...,
		)
	}

	return append(roles, xtypes.Map[string, Role](mng.roles).Values()...)
}

// Roles returns all or selected roles
func (mng *Manager) RegisterRole(ctx context.Context, roles ...Role) *Manager {
	for i, role := range roles {
		roles[i] = mng.prepareRole(ctx, role)
	}
	mng.mx.Lock()
	defer mng.mx.Unlock()
	for _, role := range roles {
		mng.roles[role.Name()] = role
	}
	return mng
}

// AddRole to the manager
func (mng *Manager) Permission(name string) Permission {
	mng.mx.RLock()
	defer mng.mx.RUnlock()
	return mng.permissions[name]
}

// Permissions returns all or selected permissions
func (mng *Manager) Permissions(patterns ...string) []Permission {
	mng.mx.RLock()
	defer mng.mx.RUnlock()

	allPermissions := xtypes.Map[string, Permission](mng.permissions).Values()

	// Return all permissions
	if len(patterns) == 0 || len(patterns) == 1 && patterns[0] == `*` {
		return allPermissions
	}

	// Filter by patterns
	return allPermissions.Filter(func(perm Permission) bool {
		for _, pattern := range patterns {
			if perm.MatchPermissionPattern(pattern) {
				return true
			}
		}
		return false
	})
}

// ObjectPermissions returns all or selected permissions for the object like .RBACResourceName() + `.` + pattern
func (mng *Manager) ObjectPermissions(obj any, patterns ...string) []Permission {
	if item := mng.objectItem(obj); item != nil {
		if len(patterns) == 0 || len(patterns) == 1 && patterns[0] == `*` {
			return mng.Permissions(GetResName(obj) + `.*`)
		}
		return mng.Permissions(xtypes.Slice[string](patterns).Apply(
			func(pattern string) string { return GetResName(obj) + `.` + pattern },
		)...)
	}
	return nil
}

// RegisterPermission in the system
func (mng *Manager) RegisterPermission(perms ...Permission) *Manager {
	mng.mx.Lock()
	defer mng.mx.Unlock()
	for _, perm := range perms {
		mng.permissions[perm.Name()] = perm
	}
	return mng
}

// RegisterNewPermission in the system
func (mng *Manager) RegisterNewPermission(resType any, name string, options ...Option) error {
	return mng.RegisterNewPermissions(resType, []string{name}, options...)
}

// RegisterNewPermissions multiple related to the resource type
func (mng *Manager) RegisterNewPermissions(resType any, names []string, options ...Option) error {
	permissions := make([]Permission, 0, len(names))

	if resType == nil {
		// Register simple permissions
		for _, name := range names {
			perm, err := NewSimplePermission(name, options...)
			if err != nil {
				return err
			}
			permissions = append(permissions, perm)
		}
	} else {
		// Register resource permissions
		if obj := mng.objectItem(resType); obj != nil && obj.checkCallbac != nil {
			options = append([]Option{WithCustomCheck(obj.checkCallbac)}, options...)
		}
		for _, name := range names {
			perm, err := NewResourcePermission(name, resType, options...)
			if err != nil {
				return err
			}
			permissions = append(permissions, perm)
		}
	}

	_ = mng.RegisterPermission(permissions...)
	return nil
}

// RegisterNewOwningPermissions modifies permissions for owning with extension of the name > name.owner, name.account and name.all
func (mng *Manager) RegisterNewOwningPermissions(resType any, names []string, options ...Option) error {
	if resType == nil {
		return ErrResourceTypeRequired
	}

	newNames := make([]string, 0, len(names)*len(owningTypes))
	for _, name := range names {
		for _, own := range owningTypes {
			newNames = append(newNames, name+`.`+own)
		}
	}
	return mng.RegisterNewPermissions(resType, newNames, options...)
}

func (mng *Manager) prepareRole(ctx context.Context, role Role) Role {
	switch rolei := role.(type) {
	case rolePreparer:
		role = rolei.Prepare(ctx, mng)
	default:
	}
	return role
}
