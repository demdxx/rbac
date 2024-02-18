package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRole(t *testing.T) {
	ctx := context.TODO()

	role, err := NewRole(`test`, WithChildRoles(MustNewRole(`viewer`)))
	assert.NoError(t, err, `NewRole`)
	assert.Equal(t, `test`, role.Name())
	assert.False(t, role.CheckPermissions(ctx, &testObject{}, `view`))
	assert.Nil(t, role.Permission(`view`))
}

func TestViewRole(t *testing.T) {
	ctx := context.TODO()
	viewer := MustNewRole(`viewer`, WithPermissions(
		MustNewSimplePermission(`view1`),
		MustNewResourcePermission(`view2`, (*testObject)(nil)),
		MustNewResourcePermission(`view3`, (*testObject)(nil), WithCustomCheck(testCustomCallback)),
	))
	role, err := NewRole(`test`, WithChildRoles(viewer))
	assert.NoError(t, err, `NewRole`)
	assert.Equal(t, `test`, role.Name())
	assert.True(t, role.HasRole(`test`))
	assert.True(t, role.HasRole(`viewer`))
	assert.False(t, role.HasRole(`fail`))
	assert.True(t, role.CheckPermissions(ctx, &testObject{name: `test`}, `view1`))
	assert.True(t, role.CheckPermissions(ctx, &testObject{name: `test`}, `view2`))
	assert.True(t, role.CheckPermissions(ctx, &testObject{name: `test`}, `view3`))
	assert.NotNil(t, role.CheckedPermissions(ctx, &testObject{name: `test`}, `view1`))
	assert.True(t, role.HasPermission(`view1`))
	assert.False(t, role.HasPermission(`view-bad`))
	assert.Panics(t, func() { role.CheckPermissions(ctx, nil) })
	assert.Equal(t, 0, len(role.ChildPermissions()))

	assert.NotNil(t, role.Permission(`view1`))
	assert.NotNil(t, role.Permission(`rbac.testObject.view2`))

	if assert.Equal(t, 1, len(role.ChildRoles())) {
		assert.Equal(t, `viewer`, role.ChildRoles()[0].Name())
		assert.Equal(t, 3, len(role.ChildRoles()[0].ChildPermissions()))
	}
}

func TestNewRoleError(t *testing.T) {
	_, err := NewRole(`test`, WithCustomCheck(nil))
	assert.NotNil(t, err, `NewRole`)
}
