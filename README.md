# RBAC module for Go

[![Build Status](https://github.com/demdxx/rbac/workflows/run%20tests/badge.svg)](https://github.com/demdxx/rbac/actions?workflow=run%20tests)
[![Go Report Card](https://goreportcard.com/badge/github.com/demdxx/rbac)](https://goreportcard.com/report/github.com/demdxx/rbac)
[![GoDoc](https://godoc.org/github.com/demdxx/rbac?status.svg)](https://godoc.org/github.com/demdxx/rbac)
[![Coverage Status](https://coveralls.io/repos/github/demdxx/rbac/badge.svg)](https://coveralls.io/github/demdxx/rbac)

RBAC (Role-Based Access Control) is a powerful module for Go that simplifies access control in your applications. It allows you to manage roles and permissions, making it easier to control who can perform specific actions within your system.

## Features

- **Role Definitions:** Create roles with associated permissions to represent different user roles or access levels.
- **Permission Checks:** Easily check if a user or entity has the required permissions to perform actions.
- **Customizable Checks:** Implement custom permission checks using callback functions to adapt the module to your specific needs.
- **Integration:** Seamlessly integrate RBAC into your Go applications to enhance security and access control.

## Installation

You can install the RBAC module using Go's package manager:

```bash
go get github.com/demdxx/rbac
```

## Usage

Here's a simple example of how to use RBAC in your Go application:

```go
import (
    "context"
    "fmt"

    "your/package/model" // Import your application's model

    "github.com/demdxx/rbac"
)

// Define a callback function for custom permission checks
callback := func(ctx context.Context, resource any, names ...string) bool {
    // Implement your custom permission logic here
    return rbac.ExtData(ctx).(*model.RoleContext).DebugMode
}

// Create an admin role with permissions and the custom check callback
adminRole := rbac.NewRole(`admin`, rbac.WithSubPermissins(
    rbac.NewSimplePermission(`access`),
    rbac.NewRosourcePermission(`view`, &model.User{}, rbac.WithCustomCheck(callback, &roleContext)),
))

// Check if a user has access and view permissions
if adminRole.CheckPermissions(ctx, userObject, `access`) {
    if !adminRole.CheckPermissions(ctx, userObject, `view`) {
        return ErrNoViewPermissions
    }
    fmt.Println("Access granted")
}
```

For detailed usage and further documentation, please refer to the [GoDoc](https://godoc.org/github.com/demdxx/rbac) documentation.

## License

This RBAC module is distributed under the Apache 2.0 License. For more information, please see the LICENSE file.

## Contributing

Contributions are welcome! If you encounter issues or have suggestions for improvement, please open an issue or submit a pull request on the GitHub repository.
