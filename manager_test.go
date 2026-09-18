package rbac

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRoleLoader struct{}

func (trl *testRoleLoader) ListRoles(ctx context.Context) []Role {
	return []Role{
		MustNewRole(`test`,
			WithChildRoles(
				MustNewRole(`viewer`, WithPermissions(
					// Register wildcard permissions preloading
					`rbac.*.view.*`,
					`rbac.*.list.*`,
				)),
				MustNewRole(`editor`, WithPermissions(
					`rbac.*.create.*`,
					`rbac.*.update.*`,
					`rbac.*.delete.*`,
				)),
			),
			WithPermissions(
				MustNewSimplePermission(`custom.permission`),
			),
		),
	}
}

func TestManager(t *testing.T) {
	ctx := context.Background()
	tm := NewManagerWithLoader(&testRoleLoader{}, time.Minute*5)
	tm.
		RegisterObject(&testExt{}, nil).
		RegisterObject(&testObject{}, func(ctx context.Context, resource any, perm Permission) bool {
			return strings.HasSuffix(perm.Name(), `.all`)
		})

	// Register new permissions
	assert.NoError(t, tm.RegisterNewOwningPermissions(
		(*testObject)(nil),
		[]string{`view`, `list`, `create`, `update`, `delete`}))
	assert.NoError(t, tm.RegisterNewOwningPermissions(
		(*testExt)(nil),
		[]string{`view`, `list`, `create`, `update`, `delete`},
		WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
			return strings.HasSuffix(perm.Name(), `.all`)
		}),
	))
	assert.NoError(t, tm.RegisterNewPermission(nil, `custom.permission.notused`))
	assert.NoError(t, tm.RegisterNewPermissions(nil, []string{
		`custom.permission.notused2`,
		`custom.permission.notused3`,
	}))

	// Register role with permissions of the system administrator
	tm.RegisterRole(ctx, MustNewRole(`admin`, WithPermissions(`rbac.*.*.all`)))

	// Check object reading
	assert.NotNil(t, tm.ObjectByName(GetResName((*testObject)(nil))))
	assert.Nil(t, tm.ObjectByName(`not.exists`))

	// Check permissions
	assert.Equal(t, 33, len(tm.Permissions()))
	assert.Equal(t, 15, len(tm.ObjectPermissions((*testObject)(nil))))
	assert.Equal(t, 5, len(tm.ObjectPermissions((*testObject)(nil), `*.owner`)))
	assert.Equal(t, 0, len(tm.ObjectPermissions(nil)))

	assert.Equal(t, 2, len(tm.Roles(ctx)))
	assert.Equal(t, 2, len(tm.Roles(ctx, `test`, `admin`)))
	assert.Equal(t, 1, len(tm.Roles(ctx, `admin`)))

	assert.Equal(t, 2, len(tm.RolesByFilter(ctx, func(context.Context, Role) bool { return true })))
	assert.Equal(t, 1, len(tm.RolesByFilter(ctx, func(ctx context.Context, role Role) bool {
		return role.HasPermission(`custom.permission`)
	})))

	assert.Nil(t, tm.Permission(`not.exists`))
	assert.NotNil(t, tm.Permission(`rbac.testObject.view.owner`))

	// Check test role from loader
	role := tm.Role(ctx, `test`)
	if assert.NotNil(t, role) {
		assert.Equal(t, `test`, role.Name())
		assert.True(t, role.HasPermission(`custom.permission`))
		assert.True(t, role.HasPermission(`rbac.testObject.view.*`))
		assert.Equal(t, 31, len(role.Permissions()))
		assert.True(t, role.CheckPermissions(ctx, &testObject{}, `view.*`))
		assert.True(t, role.CheckPermissions(ctx, &testExt{}, `view.*`))
	}

	// Check custom admin role
	role = tm.Role(ctx, `admin`)
	if assert.NotNil(t, role) {
		assert.Equal(t, `admin`, role.Name())
		assert.True(t, role.HasPermission(`rbac.*.*.all`))
		assert.Equal(t, 10, len(role.Permissions()))
		assert.True(t, role.CheckPermissions(ctx, &testObject{}, `view.*`))
		assert.True(t, role.CheckPermissions(ctx, &testExt{}, `view.*`))
	}
}

func TestRegisterNewOwningPermissionsRequiresType(t *testing.T) {
	tm := NewManager(nil)
	assert.ErrorIs(t, tm.RegisterNewOwningPermissions(nil, []string{`view`}), ErrResourceTypeRequired)
}

func TestRegisterObjectVsRegisterResource(t *testing.T) {
	ctx := context.Background()

	t.Run(`object requires type`, func(t *testing.T) {
		tm := NewManager(nil)
		tm.RegisterObject((*namedUser)(nil), nil)
		require.NoError(t, tm.RegisterNewPermission((*namedUser)(nil), `view`))
		role := MustNewRole(`r`, WithPermissions(tm.Permission(`user.view`)))

		assert.True(t, role.CheckPermissions(ctx, &namedUser{}, `view`))
		assert.False(t, role.CheckPermissions(ctx, &userAccess{Owner: true}, `view`))
		assert.False(t, role.CheckPermissions(ctx, &namedPost{}, `view`))
	})

	t.Run(`resource matches name without type`, func(t *testing.T) {
		var seen any
		tm := NewManager(nil)
		tm.RegisterResource((*namedUser)(nil), func(ctx context.Context, resource any, perm Permission) bool {
			seen = resource
			if access, ok := resource.(*userAccess); ok {
				return access.Owner
			}
			return true
		})
		require.NoError(t, tm.RegisterNewPermission((*namedUser)(nil), `view`))
		role := MustNewRole(`r`, WithPermissions(tm.Permission(`user.view`)))

		assert.True(t, role.CheckPermissions(ctx, &namedUser{}, `view`))
		assert.True(t, role.CheckPermissions(ctx, &userAccess{Owner: true}, `view`))
		assert.Equal(t, &userAccess{Owner: true}, seen)
		assert.False(t, role.CheckPermissions(ctx, &userAccess{Owner: false}, `view`))
		assert.False(t, role.CheckPermissions(ctx, &namedPost{}, `view`))
	})
}
