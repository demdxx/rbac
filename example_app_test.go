package rbac_test

import (
	"context"
	"strings"
	"testing"

	"github.com/demdxx/rbac"
	"github.com/stretchr/testify/suite"
)

type actorKey struct{}

type actor struct {
	UserID    uint64
	AccountID uint64
}

func withActor(ctx context.Context, userID, accountID uint64) context.Context {
	return context.WithValue(ctx, actorKey{}, actor{UserID: userID, AccountID: accountID})
}

func actorFrom(ctx context.Context) actor {
	a, _ := ctx.Value(actorKey{}).(actor)
	return a
}

type User struct {
	ID        uint64
	AccountID uint64
}

func (*User) RBACResourceName() string  { return `user` }
func (u *User) OwnerUserID() uint64     { return u.ID }
func (u *User) OwnerAccountID() uint64  { return u.AccountID }

type UserAccess struct {
	Owner     bool
	AccountID uint64
}

func (*UserAccess) RBACResourceName() string { return `user` }

type Account struct {
	ID      uint64
	OwnerID uint64
}

func (*Account) RBACResourceName() string { return `account` }
func (a *Account) OwnerUserID() uint64    { return a.OwnerID }
func (a *Account) OwnerAccountID() uint64 { return a.ID }

type Post struct {
	ID        uint64
	AuthorID  uint64
	AccountID uint64
}

func (*Post) RBACResourceName() string { return `post` }
func (p *Post) OwnerUserID() uint64    { return p.AuthorID }
func (p *Post) OwnerAccountID() uint64 { return p.AccountID }

type PostAccess struct {
	Owner     bool
	AccountID uint64
}

func (*PostAccess) RBACResourceName() string { return `post` }

type ownerUser interface {
	OwnerUserID() uint64
}

type ownerAccount interface {
	OwnerAccountID() uint64
}

func appPermissionCheck(ctx context.Context, resource any, perm rbac.Permission) bool {
	cover := perm.Name()
	if i := strings.LastIndex(cover, `.`); i >= 0 {
		cover = cover[i+1:]
	}
	current := actorFrom(ctx)
	switch cover {
	case rbac.OwnAll:
		return true
	case rbac.OwnAccount:
		if access, ok := resource.(*PostAccess); ok {
			return access.AccountID != 0 && access.AccountID == current.AccountID
		}
		if access, ok := resource.(*UserAccess); ok {
			return access.AccountID != 0 && access.AccountID == current.AccountID
		}
		if acc, ok := resource.(ownerAccount); ok {
			return acc.OwnerAccountID() != 0 && acc.OwnerAccountID() == current.AccountID
		}
	case rbac.OwnOwner:
		if access, ok := resource.(*PostAccess); ok {
			return access.Owner
		}
		if access, ok := resource.(*UserAccess); ok {
			return access.Owner
		}
		if own, ok := resource.(ownerUser); ok {
			return own.OwnerUserID() != 0 && own.OwnerUserID() == current.UserID
		}
	}
	return false
}

// ExampleAppSuite imitates a small API: typed user/account, name-only posts, owning levels.
type ExampleAppSuite struct {
	suite.Suite

	ctx       context.Context
	pm        *rbac.Manager
	anonymous rbac.Role
	member    rbac.Role
	admin     rbac.Role
}

func TestExampleAppSuite(t *testing.T) {
	suite.Run(t, new(ExampleAppSuite))
}

func (s *ExampleAppSuite) SetupTest() {
	s.ctx = context.Background()
	s.pm = rbac.NewManager(nil)

	s.pm.RegisterObject((*User)(nil), appPermissionCheck)
	s.pm.RegisterObject((*Account)(nil), appPermissionCheck)
	s.pm.RegisterResource((*Post)(nil), appPermissionCheck)

	s.Require().NoError(s.pm.RegisterNewPermission(nil, `account.register`))
	s.Require().NoError(s.pm.RegisterNewOwningPermissions((*User)(nil), []string{`view`, `edit`, `list`}))
	s.Require().NoError(s.pm.RegisterNewOwningPermissions((*Account)(nil), []string{`view`, `edit`, `list`}))
	s.Require().NoError(s.pm.RegisterNewOwningPermissions((*Post)(nil), []string{`view`, `edit`, `list`}))

	s.pm.RegisterRole(s.ctx,
		rbac.MustNewRole(`anonymous`, rbac.WithPermissions(
			`account.register`,
			`post.view.owner`,
		)),
		rbac.MustNewRole(`member`, rbac.WithPermissions(
			`user.*.owner`,
			`post.*.owner`,
			`account.view.account`,
		)),
		rbac.MustNewRole(`admin`, rbac.WithPermissions(
			`account.register`,
			`*.*.all`,
		)),
	)

	s.anonymous = s.pm.Role(s.ctx, `anonymous`)
	s.member = s.pm.Role(s.ctx, `member`)
	s.admin = s.pm.Role(s.ctx, `admin`)
	s.Require().NotNil(s.anonymous)
	s.Require().NotNil(s.member)
	s.Require().NotNil(s.admin)
}

func (s *ExampleAppSuite) TestAnonymousRegister() {
	s.True(s.anonymous.CheckPermissions(s.ctx, nil, `account.register`))
	s.True(s.anonymous.CheckPermissions(s.ctx, &Account{}, `register`))
	s.False(s.anonymous.CheckPermissions(s.ctx, &Account{ID: 1}, `edit`))
}

func (s *ExampleAppSuite) TestOwnerEditsOwnPostViaDTO() {
	ctx := withActor(s.ctx, 7, 3)

	own := &PostAccess{Owner: true, AccountID: 3}
	s.True(s.member.CheckPermissions(ctx, own, `edit.owner`))
	s.True(s.member.CheckPermissions(ctx, own, `edit.*`))

	foreign := &PostAccess{Owner: false, AccountID: 9}
	s.False(s.member.CheckPermissions(ctx, foreign, `edit.owner`))
	s.False(s.anonymous.CheckPermissions(ctx, foreign, `view.owner`))
	s.True(s.anonymous.CheckPermissions(ctx, own, `view.owner`))
}

func (s *ExampleAppSuite) TestTypedUserRejectsProxy() {
	ctx := withActor(s.ctx, 7, 3)
	user := &User{ID: 7, AccountID: 3}
	proxy := &UserAccess{Owner: true, AccountID: 3}

	s.True(s.member.CheckPermissions(ctx, user, `view.owner`))
	s.False(s.member.CheckPermissions(ctx, proxy, `view.owner`))
}

func (s *ExampleAppSuite) TestAdminAll() {
	ctx := withActor(s.ctx, 1, 1)
	foreignUser := &User{ID: 99, AccountID: 8}
	foreignPost := &Post{ID: 5, AuthorID: 99, AccountID: 8}
	foreignDTO := &PostAccess{Owner: false, AccountID: 8}

	s.True(s.admin.CheckPermissions(ctx, foreignUser, `view.*`))
	s.True(s.admin.CheckPermissions(ctx, foreignPost, `view.*`))
	s.True(s.admin.CheckPermissions(ctx, foreignDTO, `edit.*`))
	s.False(s.member.CheckPermissions(ctx, foreignUser, `view.*`))
	s.False(s.member.CheckPermissions(ctx, foreignDTO, `edit.*`))
}

func (s *ExampleAppSuite) TestCrossResource() {
	ctx := withActor(s.ctx, 7, 3)
	acc := &Account{ID: 3, OwnerID: 7}

	s.True(s.member.CheckPermissions(ctx, acc, `view.account`))
	s.False(s.member.CheckPermissions(ctx, acc, `edit`))
	s.False(s.member.CheckPermissions(ctx, acc, `post.edit.owner`))
}

func (s *ExampleAppSuite) TestHasPermissionCatalog() {
	s.True(s.anonymous.HasPermission(`account.register`))
	s.True(s.member.HasPermission(`user.view.owner`))
	s.True(s.member.HasPermission(`post.*.owner`))
	s.False(s.member.HasPermission(`post.view.all`))
	s.True(s.admin.HasPermission(`post.view.all`))
	s.True(s.admin.HasPermission(`*.*.all`))
}
