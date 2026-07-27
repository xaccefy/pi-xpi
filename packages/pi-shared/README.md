# pi-shared

Internal shared utilities for XPI packages. Not intended for direct consumption.

## Exports

- `TtlLruCache<T>` — bounded TTL + LRU cache with singleflight coalescing.
- `abortableSleep(ms, signal?)` — sleep that rejects on abort.

## Usage

```ts
import { TtlLruCache } from "@xaccefy/pi-shared";
```
