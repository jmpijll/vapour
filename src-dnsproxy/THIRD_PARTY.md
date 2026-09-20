# Third-party notices

This nested module is distributed with Vapour's GPL-3.0-only source.  Direct
dependencies and their pinned upstream license texts are retained here:

| Dependency | Version | License | Upstream source |
| --- | --- | --- | --- |
| `github.com/AdguardTeam/dnsproxy` | `v0.84.2` | Apache-2.0 | [source](https://github.com/AdguardTeam/dnsproxy/tree/v0.84.2), [license](https://raw.githubusercontent.com/AdguardTeam/dnsproxy/v0.84.2/LICENSE) |
| `github.com/AdguardTeam/urlfilter` | `v0.23.4` | GPL-3.0 | [source](https://github.com/AdguardTeam/urlfilter/tree/v0.23.4), [license](https://raw.githubusercontent.com/AdguardTeam/urlfilter/v0.23.4/LICENSE) |
| `github.com/miekg/dns` | `v1.1.72` | BSD-3-Clause | [source](https://github.com/miekg/dns/tree/v1.1.72), [license](https://raw.githubusercontent.com/miekg/dns/v1.1.72/LICENSE) |
| `golang.org/x/sys` | `v0.47.0` | BSD-3-Clause | [source](https://github.com/golang/sys/tree/v0.47.0), [license](https://github.com/golang/sys/blob/v0.47.0/LICENSE) |

The corresponding license texts are:

- [`licenses/dnsproxy-Apache-2.0.txt`](licenses/dnsproxy-Apache-2.0.txt)
- [`licenses/urlfilter-GPL-3.0.txt`](licenses/urlfilter-GPL-3.0.txt)
- [`licenses/miekg-dns-BSD-3-Clause.txt`](licenses/miekg-dns-BSD-3-Clause.txt)
- [`licenses/golang-sys-BSD-3-Clause.txt`](licenses/golang-sys-BSD-3-Clause.txt)

`go.mod` and `go.sum` pin the complete module graph.  A release build should
regenerate its complete transitive notice inventory and retain every required
upstream notice alongside the binary.
