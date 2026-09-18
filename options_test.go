package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionError(t *testing.T) {
	assert.Error(t, WithChildRoles()(nil))
	assert.Error(t, WithPermissions()(nil))
	assert.Error(t, WithCustomCheck(nil)(nil))
	assert.Error(t, WithCustomCheck(func() {})(nil))
	assert.Error(t, WithCustomCheck(func() {}, []int{})(&SimplePermission{}))
	assert.Error(t, WithCustomCheck(func() {}, []int{})(&ResourcePermission{}))
}

func TestWithCustomCheckAnyResource(t *testing.T) {
	perm, err := NewResourcePermission(`view`, (*namedUser)(nil), WithMatchByResourceName(), WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
		return true
	}))
	require.NoError(t, err)
	assert.True(t, perm.CheckPermissions(context.TODO(), &userAccess{Owner: true}, `view`))
}

func TestWithMatchByResourceNameRejectsWrongType(t *testing.T) {
	assert.Error(t, WithMatchByResourceName()(&SimplePermission{}))
}

func TestWithoutCustomCheckAndExtData(t *testing.T) {
	perm := MustNewSimplePermission(`access`, WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
		return false
	}), WithExtData(`ext`))
	assert.Equal(t, `ext`, perm.Ext())
	require.NoError(t, WithoutCustomCheck(perm))
	assert.True(t, perm.CheckPermissions(context.TODO(), nil, `access`))

	role := MustNewRole(`r`, WithExtData(42))
	assert.Equal(t, 42, role.Ext())
}
