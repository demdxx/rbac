package rbac

import (
	"context"
	"testing"
)

type benchUser struct {
	ID uint64
}

func (*benchUser) RBACResourceName() string { return `user` }

type benchUserAccess struct {
	Owner bool
}

func (*benchUserAccess) RBACResourceName() string { return `user` }

func benchCallback(_ context.Context, resource any, _ Permission) bool {
	if access, ok := resource.(*benchUserAccess); ok {
		return access.Owner
	}
	return true
}

func setupTypedBench() (context.Context, Role, *benchUser) {
	ctx := context.Background()
	pm := NewManager(nil)
	pm.RegisterObject((*benchUser)(nil), benchCallback)
	if err := pm.RegisterNewPermission(nil, `account.register`); err != nil {
		panic(err)
	}
	if err := pm.RegisterNewOwningPermissions((*benchUser)(nil), []string{`view`, `edit`, `list`}); err != nil {
		panic(err)
	}
	pm.RegisterRole(ctx, MustNewRole(`member`, WithPermissions(
		`account.register`,
		`user.*.owner`,
		`user.*.all`,
	)))
	role := pm.Role(ctx, `member`)
	if role == nil {
		panic(`member role not found`)
	}
	return ctx, role, &benchUser{ID: 1}
}

func setupNamedBench() (context.Context, Role, *benchUserAccess) {
	ctx := context.Background()
	pm := NewManager(nil)
	pm.RegisterResource((*benchUser)(nil), benchCallback)
	if err := pm.RegisterNewOwningPermissions((*benchUser)(nil), []string{`view`, `edit`}); err != nil {
		panic(err)
	}
	pm.RegisterRole(ctx, MustNewRole(`member`, WithPermissions(`user.*.owner`)))
	role := pm.Role(ctx, `member`)
	if role == nil {
		panic(`member role not found`)
	}
	return ctx, role, &benchUserAccess{Owner: true}
}

func BenchmarkCheckSimplePermission(b *testing.B) {
	ctx, role, _ := setupTypedBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !role.CheckPermissions(ctx, nil, `account.register`) {
			b.Fatal(`expected allow`)
		}
	}
}

func BenchmarkCheckResourceTyped(b *testing.B) {
	ctx, role, user := setupTypedBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !role.CheckPermissions(ctx, user, `view.owner`) {
			b.Fatal(`expected allow`)
		}
	}
}

func BenchmarkCheckResourceByName(b *testing.B) {
	ctx, role, access := setupNamedBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !role.CheckPermissions(ctx, access, `view.owner`) {
			b.Fatal(`expected allow`)
		}
	}
}

func BenchmarkCheckResourceWildcard(b *testing.B) {
	ctx, role, user := setupTypedBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !role.CheckPermissions(ctx, user, `view.*`) {
			b.Fatal(`expected allow`)
		}
	}
}

func BenchmarkHasPermission(b *testing.B) {
	_, role, _ := setupTypedBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !role.HasPermission(`user.view.owner`) {
			b.Fatal(`expected allow`)
		}
	}
}

func BenchmarkExpandPermissionPatterns(b *testing.B) {
	user := &benchUser{ID: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExpandPermissionPatterns(user, `view.owner`, `edit.*`)
	}
}

func BenchmarkMatchName(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := MatchName(`user.*.owner`, `user.view.owner`)
		if err != nil || !ok {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetResName(b *testing.B) {
	user := &benchUser{ID: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if GetResName(user) != `user` {
			b.Fatal(`unexpected name`)
		}
	}
}
