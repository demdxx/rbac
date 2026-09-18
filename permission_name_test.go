package rbac

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type namedAccount struct{}

func (*namedAccount) RBACResourceName() string { return `account` }

type namedUser struct {
	owner bool
}

func (*namedUser) RBACResourceName() string { return `user` }

type userAccess struct {
	ActorID int
	Owner   bool
}

func (*userAccess) RBACResourceName() string { return `user` }

type namedPost struct{}

func (*namedPost) RBACResourceName() string { return `post` }

type customPatternObj struct{}

func (*customPatternObj) RBACResourceName() string { return `account` }

func (*customPatternObj) RBACPermissionPatterns(patterns ...string) []string {
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, `custom.`+pattern)
	}
	return out
}

func TestExpandPermissionPatterns(t *testing.T) {
	t.Run(`nil resource keeps originals`, func(t *testing.T) {
		assert.Equal(t, []string{`account.register`}, ExpandPermissionPatterns(nil, `account.register`))
	})

	t.Run(`auto prefix from resource name`, func(t *testing.T) {
		assert.Equal(t, []string{`register`, `account.register`}, ExpandPermissionPatterns(&namedAccount{}, `register`))
	})

	t.Run(`does not double prefix`, func(t *testing.T) {
		assert.Equal(t, []string{`account.register`}, ExpandPermissionPatterns(&namedAccount{}, `account.register`))
	})

	t.Run(`custom expander`, func(t *testing.T) {
		assert.Equal(t, []string{`register`, `custom.register`}, ExpandPermissionPatterns(&customPatternObj{}, `register`))
	})

	t.Run(`empty name keeps originals`, func(t *testing.T) {
		assert.Equal(t, []string{`access`}, ExpandPermissionPatterns(`plain-string`, `access`))
	})
}

func TestSimplePermissionNameResolution(t *testing.T) {
	ctx := context.TODO()
	register := MustNewSimplePermission(`account.register`)
	access := MustNewSimplePermission(`access`)
	role := MustNewRole(`r`, WithPermissions(register, access))

	t.Run(`manual full name with nil`, func(t *testing.T) {
		assert.True(t, role.CheckPermissions(ctx, nil, `account.register`))
	})

	t.Run(`manual full name with object`, func(t *testing.T) {
		assert.True(t, role.CheckPermissions(ctx, &namedAccount{}, `account.register`))
	})

	t.Run(`short pattern composed from object`, func(t *testing.T) {
		assert.True(t, role.CheckPermissions(ctx, &namedAccount{}, `register`))
	})

	t.Run(`short pattern without object does not match`, func(t *testing.T) {
		assert.False(t, role.CheckPermissions(ctx, nil, `register`))
	})

	t.Run(`legacy simple name on object`, func(t *testing.T) {
		assert.True(t, role.CheckPermissions(ctx, &namedUser{}, `access`))
		assert.True(t, role.CheckPermissions(ctx, &testObject{}, `access`))
	})
}

func TestResourcePermissionByResourceName(t *testing.T) {
	ctx := context.TODO()
	var seen any
	view, err := NewResourcePermission(`view`, (*namedUser)(nil), WithMatchByResourceName(), WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
		seen = resource
		if access, ok := resource.(*userAccess); ok {
			return access.Owner
		}
		return true
	}))
	require.NoError(t, err)
	typedView := MustNewResourcePermission(`view`, (*namedUser)(nil))
	postView := MustNewResourcePermission(`view`, (*namedPost)(nil), WithMatchByResourceName())
	role := MustNewRole(`r`, WithPermissions(view, postView))

	t.Run(`typed default denies proxy`, func(t *testing.T) {
		assert.True(t, typedView.CheckResourceName(&userAccess{Owner: true}))
		assert.False(t, typedView.CheckType(&userAccess{Owner: true}))
		assert.True(t, typedView.CheckPermissions(ctx, &namedUser{}, `view`))
		assert.False(t, typedView.CheckPermissions(ctx, &userAccess{Owner: true}, `view`))
	})

	t.Run(`same resource name different type`, func(t *testing.T) {
		assert.True(t, view.CheckResourceName(&namedUser{}))
		assert.True(t, view.CheckResourceName(&userAccess{Owner: true}))
		assert.False(t, view.CheckType(&userAccess{Owner: true}))
		assert.True(t, role.CheckPermissions(ctx, &namedUser{}, `view`))
		assert.True(t, role.CheckPermissions(ctx, &userAccess{Owner: true}, `view`))
		assert.Equal(t, &userAccess{Owner: true}, seen)
	})

	t.Run(`proxy callback can deny`, func(t *testing.T) {
		assert.False(t, role.CheckPermissions(ctx, &userAccess{Owner: false}, `view`))
	})

	t.Run(`different resource name isolated`, func(t *testing.T) {
		assert.False(t, view.CheckPermissions(ctx, &namedPost{}, `view`))
		assert.True(t, postView.CheckPermissions(ctx, &namedPost{}, `view`))
		assert.False(t, postView.CheckPermissions(ctx, &namedUser{}, `view`))
	})

	t.Run(`nil resource does not grant resource permission`, func(t *testing.T) {
		assert.False(t, view.CheckPermissions(ctx, nil, `user.view`))
		assert.False(t, view.CheckPermissions(ctx, nil, `view`))
	})

	t.Run(`empty resource name does not match`, func(t *testing.T) {
		assert.False(t, view.CheckPermissions(ctx, `plain-string`, `view`))
	})
}

func TestOwningLevels(t *testing.T) {
	ctx := context.TODO()
	owner := MustNewResourcePermission(`view.owner`, (*namedUser)(nil), WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
		return strings.HasSuffix(perm.Name(), `.owner`)
	}))
	all := MustNewResourcePermission(`view.all`, (*namedUser)(nil), WithCustomCheck(func(ctx context.Context, resource any, perm Permission) bool {
		return strings.HasSuffix(perm.Name(), `.all`)
	}))

	ownerRole := MustNewRole(`owner`, WithPermissions(owner))
	allRole := MustNewRole(`all`, WithPermissions(all))
	both := MustNewRole(`both`, WithPermissions(owner, all))
	user := &namedUser{}

	assert.True(t, ownerRole.CheckPermissions(ctx, user, `view.owner`))
	assert.False(t, ownerRole.CheckPermissions(ctx, user, `view.all`))
	assert.True(t, ownerRole.CheckPermissions(ctx, user, `view.*`))

	assert.True(t, allRole.CheckPermissions(ctx, user, `view.all`))
	assert.False(t, allRole.CheckPermissions(ctx, user, `view.owner`))
	assert.True(t, allRole.CheckPermissions(ctx, user, `view.*`))

	assert.True(t, both.CheckPermissions(ctx, user, `view.owner`))
	assert.True(t, both.CheckPermissions(ctx, user, `view.all`))
}

func TestCallbackTypeMismatchNoPanic(t *testing.T) {
	ctx := context.TODO()
	perm := MustNewSimplePermission(`access`, WithCustomCheck(func(ctx context.Context, obj *namedUser, _ Permission) bool {
		return obj.owner
	}))
	assert.False(t, perm.CheckPermissions(ctx, &namedPost{}, `access`))
	assert.False(t, perm.CheckPermissions(ctx, nil, `access`))
	assert.True(t, perm.CheckPermissions(ctx, &namedUser{owner: true}, `access`))
}

func TestPermissionsNoDuplicates(t *testing.T) {
	child := MustNewSimplePermission(`child`)
	parent := MustNewSimplePermission(`parent`, WithPermissions(child))
	got := parent.Permissions(`child`)
	assert.Equal(t, 1, len(got))
	assert.Equal(t, `child`, got[0].Name())
}

func TestRoleCycleGuard(t *testing.T) {
	ctx := context.TODO()
	a := MustNewRole(`a`).(*role)
	b := MustNewRole(`b`).(*role)
	a.roles = []Role{b}
	b.roles = []Role{a}

	assert.False(t, a.CheckPermissions(ctx, nil, `missing`))
	assert.Nil(t, a.CheckedPermissions(ctx, nil, `missing`))
	assert.Nil(t, a.Permission(`missing`))
	assert.Empty(t, a.Permissions(`missing`))
	assert.True(t, a.HasRole(`a`))
	assert.True(t, a.HasRole(`b`))
	assert.False(t, a.HasRole(`c`))
}
