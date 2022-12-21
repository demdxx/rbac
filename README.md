# RBAC module

[![Build Status](https://github.com/demdxx/rbac/workflows/run%20tests/badge.svg)](https://github.com/demdxx/rbac/actions?workflow=run%20tests)
[![Go Report Card](https://goreportcard.com/badge/github.com/demdxx/rbac)](https://goreportcard.com/report/github.com/demdxx/rbac)
[![GoDoc](https://godoc.org/github.com/demdxx/rbac?status.svg)](https://godoc.org/github.com/demdxx/rbac)
[![Coverage Status](https://coveralls.io/repos/github/demdxx/rbac/badge.svg)](https://coveralls.io/github/demdxx/rbac)

> License Apache 2.0

**RBAC** module for GO

```go
callback := func(ctx context.Context, resource any, names ...string) bool {
  return rbac.ExtData(ctx).(*model.RoleContext).DebugMode
}

adminRole := NewRole(`admin`, WithSubPermissins(
  NewSimplePermission(`access`),
  NewRosourcePermission(`view`, &model.User{}, WithCustomCheck(callback, &roleContext)),
))

// ...

if adminRole.CheckPermissions(ctx, userObject, `access`) {
  if !adminRole.CheckPermissions(ctx, userObject, `view`) {
    return ErrNoViewPermissions
  }
  fmt.Println("Access granted")
}
```

> Access granted
