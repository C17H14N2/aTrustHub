# Third-party code

`cedar/` and `mayaqua/` are derived from
[go-softether](https://github.com/march1993/go-softether) (licensed AGPL-3.0,
the same licence as this project), a proof-of-concept SoftEther client. They are
vendored here because the project is unmaintained and two changes were
required:

- the platform adapter (utun/BPF) is removed: this backend never creates a
  system interface;
- the login packet is built by hand in `client.go`, because this hub family
  rejects the newer `NodeInfo`/`WinVer` structures with `ERR_PROTOCOL_ERROR`.

The frame transport, DHCP client, gVisor L2 bridging and session management
are original to this project.
