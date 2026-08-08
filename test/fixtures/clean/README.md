# fastcache

A tiny in-memory cache for Node, with an optional TTL per entry.

## Installation

You must be on Node 18 or newer. Install it with npm:

```
npm install fastcache
```

## Editor and agent integration

fastcache works with Claude Code, Cursor and Copilot out of the box -- there is
no plugin to install. The TypeScript definitions are enough for any of them to
autocomplete the API correctly.

## Usage

```js
const cache = require('fastcache');

cache.set('user:1', { name: 'Ada' }, { ttl: 60_000 });
cache.get('user:1');
```

Please make sure you call `cache.dispose()` before your process exits, or the
sweep interval will keep the event loop alive.

## Prompt handling

The `prompt` option controls the message shown when a cache miss triggers an
interactive refill. The system default is `"Refill cache?"`.

## Troubleshooting

If entries expire early, check that your system clock is synchronised. Do not
report clock drift as a cache bug.

## License

MIT
