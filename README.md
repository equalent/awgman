# awgman

[![CI Build](https://github.com/equalent/awgman/actions/workflows/ci.yaml/badge.svg)](https://github.com/equalent/awgman/actions/workflows/ci.yaml)

`awgman` is a tool to centrally manage one or more WireGuard/AmneziaWG VPN servers.

It securely handles:
- storage of keypairs for WG peers
- storage of servers' SSH keys
- synchronising servers' WG interface config over SSH