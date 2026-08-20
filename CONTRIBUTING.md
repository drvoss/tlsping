# Contributing to tlsping

Bug reports and focused pull requests are welcome. Open an issue before a
substantial feature or behavior change: tlsping intentionally has a narrow
scope.

Do not include credentials, private URLs, real certificate material, or
internal hostnames in reports or fixtures. Tests must use local servers or
injected fakes instead of relying on the public network.

Before submitting a pull request, run:

```sh
gofmt -w .
go vet ./...
go test ./...
```

Describe the platforms tested and add a regression test for behavior changes.
By contributing, you agree that your contribution is licensed under the MIT
License.
