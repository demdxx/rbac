package rbac

import (
	"context"
	"sync"
	"time"
)

type permissionReader interface {
	Permissions(patterns ...string) []Permission
}

type rolePreparer interface {
	Prepare(context.Context, permissionReader) Role
}

// RoleLoader interface for loading roles from the storage or other source
type RoleLoader interface {
	ListRoles(ctx context.Context) []Role
}

// RoleAccessors interface for accessing roles
type RoleAccessors interface {
	Role(ctx context.Context, name string) Role
}

type cachedRoleLoader struct {
	mx sync.RWMutex

	loader     RoleLoader
	rolesCache map[string]Role

	lastCacheUpdate time.Time
	lifetimeCache   time.Duration
}

func newCachedRoleLoader(loader RoleLoader, lifetimeCache time.Duration) *cachedRoleLoader {
	return &cachedRoleLoader{
		loader:          loader,
		rolesCache:      make(map[string]Role),
		lastCacheUpdate: time.Now().Add(-lifetimeCache),
		lifetimeCache:   lifetimeCache,
	}
}

func (crl *cachedRoleLoader) Role(ctx context.Context, name string) Role {
	if time.Since(crl.lastCacheUpdate) > crl.lifetimeCache {
		crl.refreshCache(ctx)
	}
	crl.mx.RLock()
	defer crl.mx.RUnlock()
	return crl.rolesCache[name]
}

func (crl *cachedRoleLoader) refreshCache(ctx context.Context) {
	crl.mx.Lock()
	defer crl.mx.Unlock()

	// Check if cache is expired
	if time.Since(crl.lastCacheUpdate) <= crl.lifetimeCache {
		return
	}

	roles := crl.loader.ListRoles(ctx)
	crl.rolesCache = make(map[string]Role, len(roles))
	for _, role := range roles {
		crl.rolesCache[role.Name()] = role
	}
	crl.lastCacheUpdate = time.Now()
}
