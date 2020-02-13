# resolv

The missing function from [net](https://golang.org/pkg/net/) package

---

This package provides local DNS resolver IP addresses used by the macOS system.

## Installation

Use the go command:

```sh
go get -u github.com/romantomjak/resolv
```

## Example

```go
package main

import (
	"fmt"

	"github.com/romantomjak/resolv"
)

func main() {
	addrs, err := resolv.ServerAddrs()
	if err != nil {
		panic(err)
	}

	for k, v := range addrs {
		fmt.Printf("DNS Resolver #%d: %s\n", k, v)
	}
}
```

## License

MIT
