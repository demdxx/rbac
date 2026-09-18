# RBAC module for Go

[![Build Status](https://github.com/demdxx/rbac/workflows/run%20tests/badge.svg)](https://github.com/demdxx/rbac/actions?workflow=run%20tests)
[![Go Report Card](https://goreportcard.com/badge/github.com/demdxx/rbac)](https://goreportcard.com/report/github.com/demdxx/rbac)
[![GoDoc](https://godoc.org/github.com/demdxx/rbac?status.svg)](https://godoc.org/github.com/demdxx/rbac)
[![Coverage Status](https://coveralls.io/repos/github/demdxx/rbac/badge.svg)](https://coveralls.io/github/demdxx/rbac)

Role-based access control for Go. The **permission name** is the basis of every check. An object is optional: it can compose the name and supply data for a callback. A Go type constraint is extra and only applies when you register a typed object.

## Features

- **Roles** with nested roles and permission preload by pattern.
- **SimplePermission** — named right (`account.register`, `access`). Works with or without an object.
- **ResourcePermission** — `{resource}.{action}[.{owner|account|all}]`.
- **RegisterObject** — match by name **and** Go type (`CheckType`).
- **RegisterResource** — match by name **and** `RBACResourceName()` only (DTO/proxy allowed).
- **Name resolution** — full name, or short pattern + object (`register` + Account → `account.register`).
- **Owning suffixes** — `RegisterNewOwningPermissions` builds `.owner` / `.account` / `.all`. Instance rules live in your callback.
- **Custom checks** — `func(ctx context.Context, resource any, perm Permission) bool`.

## Permission names

| Style | Example | What happens |
| --- | --- | --- |
| Manual | `account.register`, `user.view.owner` | Used as-is |
| Automatic | `register` + object with `RBACResourceName() == "account"` | Also tries `account.register` |
| Custom | `RBACPermissionPatterns(...)` on the object | Extra patterns from the object; originals are kept |

`GetResName` uses `RBACResourceName()` when present, otherwise `package.Type`.

`view.*` matches `view.owner`, `view.account`, and `view.all`. Who is the owner is **not** built in — implement that in the callback.

`HasPermission` is a catalog check (no object, no callback). `CheckPermissions` authorizes a call.

## RegisterObject vs RegisterResource

```text
CheckPermissions
  → expand patterns from the object
  → match permission name
  → RegisterObject: also CheckType
  → RegisterResource / WithMatchByResourceName: also same RBACResourceName
  → optional callback
```

- **Object** (default `NewResourcePermission`): same name + same Go type. A DTO with the same resource name is denied.
- **Resource**: same name + same `RBACResourceName`. A `PostAccess` DTO can stand in for `Post` and carry `Owner` / `AccountID`.

Direct `NewResourcePermission` is typed unless you pass `WithMatchByResourceName()`.

## Installation

```bash
go get github.com/demdxx/rbac
```

## Usage

Runnable end-to-end cases live in [`example_app_test.go`](example_app_test.go) (`TestExampleAppSuite`).

```go
package app

import (
    "context"
    "strings"

    "github.com/demdxx/rbac"
)

type User struct {
    ID        uint64
    AccountID uint64
}

func (*User) RBACResourceName() string { return "user" }

type Post struct {
    AuthorID  uint64
    AccountID uint64
}

func (*Post) RBACResourceName() string { return "post" }

// DTO for checks that need extra fields the entity does not have.
type PostAccess struct {
    Owner     bool
    AccountID uint64
}

func (*PostAccess) RBACResourceName() string { return "post" }

func cover(perm rbac.Permission) string {
    name := perm.Name()
    if i := strings.LastIndex(name, "."); i >= 0 {
        return name[i+1:]
    }
    return name
}

func check(ctx context.Context, resource any, perm rbac.Permission) bool {
    switch cover(perm) {
    case rbac.OwnAll:
        return true
    case rbac.OwnOwner:
        if a, ok := resource.(*PostAccess); ok {
            return a.Owner
        }
        return false
    default:
        return false
    }
}

func setup(ctx context.Context) *rbac.Manager {
    pm := rbac.NewManager(nil)

    // Typed: *User only. A UserAccess DTO with name "user" will not match.
    pm.RegisterObject((*User)(nil), check)

    // Name-only: *Post or PostAccess with RBACResourceName() == "post".
    pm.RegisterResource((*Post)(nil), check)

    _ = pm.RegisterNewPermission(nil, "account.register")
    _ = pm.RegisterNewOwningPermissions((*User)(nil), []string{"view", "edit"})
    _ = pm.RegisterNewOwningPermissions((*Post)(nil), []string{"view", "edit"})

    pm.RegisterRole(ctx,
        rbac.MustNewRole("anonymous", rbac.WithPermissions(
            "account.register",
            "post.view.owner",
        )),
        rbac.MustNewRole("member", rbac.WithPermissions(
            "user.*.owner",
            "post.*.owner",
        )),
        rbac.MustNewRole("admin", rbac.WithPermissions(
            "account.register",
            "*.*.all",
        )),
    )
    return pm
}

func example(ctx context.Context, pm *rbac.Manager) {
    member := pm.Role(ctx, "member")
    admin := pm.Role(ctx, "admin")
    anonymous := pm.Role(ctx, "anonymous")

    // SimplePermission: full name, or short name + object.
    _ = anonymous.CheckPermissions(ctx, nil, "account.register")
    _ = anonymous.CheckPermissions(ctx, &struct{ n string }{}, "account.register") // still matches by name

    // Resource + DTO (RegisterResource).
    own := &PostAccess{Owner: true}
    _ = member.CheckPermissions(ctx, own, "edit.owner")
    _ = member.CheckPermissions(ctx, own, "edit.*")

    // Catalog (no instance check).
    _ = admin.HasPermission("post.view.all")
}
```

Without `RBACResourceName()`, the name is `package.Type` (for example `rbac.testObject`).

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome.
