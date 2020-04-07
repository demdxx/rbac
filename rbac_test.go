package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRole(t *testing.T) {
	role, err := NewRole(`test`, WithChildRoles(MustNewRole(`viewer`)))
	assert.NoError(t, err, `NewRole`)
	assert.Equal(t, `test`, role.Name())
	assert.False(t, role.CheckPermissions(&testObject{}, `view`))
}

func TestViewRole(t *testing.T) {
	viewer := MustNewRole(`viewer`, WithSubPermissins(
		MustNewSimplePermission(`view1`),
		MustNewRosourcePermission(`view2`, (*testObject)(nil)),
		MustNewRosourcePermission(`view3`, (*testObject)(nil), WithCustomCheck(testCustomCallback)),
	))
	role, err := NewRole(`test`, WithChildRoles(viewer))
	assert.NoError(t, err, `NewRole`)
	assert.Equal(t, `test`, role.Name())
	assert.True(t, role.CheckPermissions(&testObject{name: `test`}, `view1`))
	assert.True(t, role.CheckPermissions(&testObject{name: `test`}, `view2`))
	assert.True(t, role.CheckPermissions(&testObject{name: `test`}, `view3`))
}

func TestNewRoleError(t *testing.T) {
	_, err := NewRole(`test`, WithCustomCheck(nil))
	assert.NotNil(t, err, `NewRole`)
}
