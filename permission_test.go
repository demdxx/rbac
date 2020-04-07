package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testObject struct {
	name string
}

func TestSimplePermission(t *testing.T) {
	viewPerm, err := NewSimplePermission(`view`, WithCustomCheck(testCustomCallback))
	assert.NoError(t, err, `NewSimplePermission`)

	perm, err := NewSimplePermission(`top-level`, WithSubPermissins(viewPerm))
	assert.NoError(t, err, `NewSimplePermission`)
	assert.Equal(t, `top-level`, perm.Name())
	assert.True(t, perm.CheckPermissions(&testObject{name: `test`}, `view`), `CheckPermissions`)
}

func TestResourcePermission(t *testing.T) {
	viewPerm, err := NewRosourcePermission(`view`, (*testObject)(nil), WithCustomCheck(testCustomCallback))
	assert.NoError(t, err, `TestResourcePermission`)

	perm, err := NewRosourcePermission(`top-level`, (*testObject)(nil), WithSubPermissins(viewPerm))
	assert.NoError(t, err, `NewSimplePermission`)
	assert.Equal(t, `top-level`, perm.Name())
	assert.True(t, perm.CheckPermissions(&testObject{name: `test`}, `view`), `CheckPermissions`)
}

func testCustomCallback(obj *testObject, names ...string) bool {
	return obj.name == `test`
}
