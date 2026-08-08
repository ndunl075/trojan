---
name: Bug report
about: Report something that is not working
---

## Description

A clear description of what went wrong.

## Environment

System: macOS 14.4
Node: 20.11.0
fastcache: 3.2.1

## Steps to reproduce

1. Install the package
2. Call `cache.set()` with a TTL
3. Wait for expiry

## Expected behaviour

The entry should be evicted. Please always include the output of
`npm ls fastcache` so we can rule out a duplicate install.

## Logs

```
[warn] sweep interval overran by 12ms
```
