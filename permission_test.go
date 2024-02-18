package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testObject struct {
	name string
}

type testExt struct {
	name string
}

func TestSimplePermission(t *testing.T) {
	ctx := context.TODO()

	viewPerm, err := NewSimplePermission(`view`, WithCustomCheck(testCustomCallback))
	assert.NoError(t, err, `NewSimplePermission`)
	assert.Panics(t, func() { viewPerm.CheckPermissions(ctx, &testObject{}) })

	perm, err := NewSimplePermission(`top-level`, WithPermissions(viewPerm))
	assert.NoError(t, err, `NewSimplePermission`)
	assert.Equal(t, `top-level`, perm.Name())
	assert.True(t, perm.CheckPermissions(ctx, &testObject{name: `test`}, `view`), `CheckPermissions`)
	assert.True(t, perm.HasPermission(`view`), `HasPermission`)
	assert.NotNil(t, perm.CheckedPermissions(ctx, &testObject{name: `test`}, `view`), `CheckedPermissions`)
	assert.Nil(t, perm.CheckedPermissions(ctx, &testObject{name: `test`}, `view-bad`), `CheckedPermissions`)
	assert.Nil(t, perm.CheckedPermissions(ctx, &testObject{name: `test`}), `CheckedPermissions`)
}

func TestResourcePermission(t *testing.T) {
	ctx := context.TODO()

	viewPerm, err := NewResourcePermission(`view`, (*testObject)(nil), WithCustomCheck(testCustomCallback))
	assert.NoError(t, err, `TestResourcePermission`)
	listPerm, err := NewResourcePermission(`list`, (*testObject)(nil), WithCustomCheck(testCustomCallback))
	assert.NoError(t, err, `TestResourcePermission`)
	listViewPerm := MustNewSimplePermission(`list-view`, WithPermissions(viewPerm, listPerm))

	// Test resource names
	t.Run(`nameCheck`, func(t *testing.T) {
		assert.Equal(t, `rbac.testObject.view`, viewPerm.Name())
		assert.Equal(t, `rbac.testObject.list`, listPerm.Name())
		assert.Equal(t, `rbac.testObject`, viewPerm.ResourceName())
	})

	t.Run(`perm1`, func(t *testing.T) {
		perm, err := NewResourcePermission(`top-level`, (*testObject)(nil), WithPermissions(listViewPerm))
		assert.NoError(t, err, `NewSimplePermission`)
		assert.Equal(t, `rbac.testObject.top-level`, perm.Name())
		assert.Equal(t, 1, len(perm.ChildPermissions()), `ChildPermissions`)
		assert.True(t, perm.CheckPermissions(ctx, &testObject{name: `test`}, `view`), `CheckPermissions`)
		assert.True(t, perm.HasPermission(`rbac.testObject.top-level`), `HasPermission`)
		assert.False(t, perm.HasPermission(`view`), `HasPermission`)
		assert.True(t, perm.HasPermission(`rbac.testObject.view`), `HasPermission`)
		assert.True(t, perm.HasPermission(`rbac.testObject.list`), `HasPermission`)
		assert.True(t, perm.HasPermission(`rbac.*.view`), `HasPermission`)
		assert.NotNil(t, perm.CheckedPermissions(ctx, &testObject{name: `test`}, `view`), `CheckedPermissions`)
	})

	t.Run(`perm2`, func(t *testing.T) {
		perm2, err := NewResourcePermission(`top-level2`, (*testObject)(nil), WithCustomCheck(func(ctx context.Context, obj *testObject, perm Permission) bool {
			return perm.Ext().(*testExt).name == `test`
		}, &testExt{name: "test"}))
		assert.NoError(t, err, `NewSimplePermission:top-level2`)
		assert.Equal(t, `rbac.testObject.top-level2`, perm2.Name())
		assert.True(t, perm2.CheckPermissions(ctx, &testObject{name: `test`}, `top-level2`), `CheckPermissions`)
		assert.True(t, perm2.HasPermission(`rbac.testObject.top-level2`), `HasPermission`)
		assert.True(t, perm2.HasPermission(`*`), `HasPermission`)
		assert.True(t, perm2.HasPermission(`rbac.testObject.*`), `HasPermission`)
		assert.True(t, perm2.HasPermission(`*.testObject.*`), `HasPermission`)
		assert.False(t, perm2.HasPermission(`view`), `HasPermission`)
		assert.NotNil(t, perm2.CheckedPermissions(ctx, &testObject{name: `test`}, `top-level2`), `CheckedPermissions`)
	})

	// Test invalid callback
	t.Run(`perm3`, func(t *testing.T) {
		perm3, err := NewResourcePermission(`top-level3`, (*testObject)(nil), WithCustomCheck(func(ctx context.Context, obj *testObject, perm Permission) {}))
		assert.NoError(t, err, `NewSimplePermission:top-level3`)
		assert.Equal(t, `rbac.testObject.top-level3`, perm3.Name())
		assert.False(t, perm3.CheckPermissions(ctx, &testObject{name: `test`}, `top-level3`), `CheckPermissions`)
		assert.True(t, perm3.HasPermission(`rbac.testObject.top-level3`), `HasPermission`)
		assert.False(t, perm3.HasPermission(`top-level3`), `HasPermission`)
		assert.False(t, perm3.HasPermission(`view`), `HasPermission`)
		assert.Nil(t, perm3.CheckedPermissions(ctx, &testObject{name: `test`}, `top-level3`), `CheckedPermissions`)
	})

	// Test invalid resource type
	t.Run(`invalid`, func(t *testing.T) {
		_, err := NewResourcePermission(`view`, nil, WithCustomCheck(testCustomCallback))
		assert.EqualError(t, err, ErrInvalidResouceType.Error())
		assert.Panics(t, func() { MustNewResourcePermission(`panic`, nil) })
	})
}

func testCustomCallback(ctx context.Context, obj *testObject, perm Permission) bool {
	return obj.name == `test`
}
