# Event pipeline: bounded asynchronous delivery

`bsdm-proxy` emits cache and policy events to Kafka or, in Lite deployments, to
an HTTP event sink. Analytics delivery is deliberately isolated from the proxy
request path: a slow broker or indexer must not add network latency to the
client response.

## Data flow

```text
proxy request
    │
    ├─ build CacheEvent (subject to KAFKA_SAMPLE_RATE)
    │
    └─ try_send
         │
         ▼
    bounded mpsc queue                 KAFKA_QUEUE_CAPACITY
         │
         ▼
    bounded concurrent delivery set    KAFKA_MAX_IN_FLIGHT
                                       EVENT_SINK_MAX_IN_FLIGHT
         │
         ├─ Kafka FutureProducer delivery future
         └─ HTTP POST future
```

The request path only performs `try_send`. It never waits for a broker ACK or an
HTTP response. When the queue is full, the pipeline applies `drop_new` and
increments `bsdm_proxy_kafka_queue_dropped_total` instead of increasing request
latency or retaining events without a memory bound.

The delivery stage is also bounded. A single worker task polls a
`FuturesUnordered` set, so several network deliveries can progress concurrently
without spawning a Tokio task per event.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `KAFKA_QUEUE_CAPACITY` | `8192` | Maximum number of events waiting in the proxy-side queue. Used by both Kafka and the Lite HTTP sink for backward compatibility. |
| `KAFKA_MAX_IN_FLIGHT` | `256` | Maximum Kafka delivery futures being polled concurrently. |
| `EVENT_SINK_MAX_IN_FLIGHT` | `16` | Maximum HTTP event requests in flight concurrently. |
| `KAFKA_SAMPLE_RATE` | `0` | `0` emits every event; `N` emits approximately one event out of `N`. |

All capacity and concurrency values must be positive integers. Invalid or zero
values fall back to their defaults.

The upper bound on events retained by this layer is approximately:

```text
KAFKA_QUEUE_CAPACITY + selected MAX_IN_FLIGHT
```

This does not include buffering internal to librdkafka, the HTTP stack, or the
consumer. Size the queue from the acceptable burst window and available memory,
not as a substitute for fixing a persistently slow downstream.

## Delivery and ordering semantics

- Delivery is **at most once from the proxy queue**: an event dropped because
  the queue is full is not retried by the proxy.
- A Kafka or HTTP send failure is counted and logged; the event is not placed
  back into the queue.
- Completion order is not guaranteed. Consumers must use `event_id`,
  `timestamp`, `session_id`, and `parent_event_id` rather than arrival order.
- Dropping all pipeline senders drains deliveries that were already accepted by
  the worker before its task exits. Process shutdown is still limited by the
  global graceful-shutdown timeout.

## Tuning procedure

1. Watch `bsdm_proxy_kafka_queue_dropped_total` and send-error counters under
   production-like burst load.
2. If drops occur while the downstream remains healthy, raise the relevant
   max-in-flight value first; this improves latency hiding without enlarging the
   waiting queue.
3. Raise `KAFKA_QUEUE_CAPACITY` only when a larger bounded burst buffer is
   operationally acceptable.
4. If the sink is continuously slower than event production, enable sampling
   or scale/fix the downstream. Increasing both bounds only delays overload.

Defaults are intentionally different: Kafka's producer is designed for many
concurrent delivery futures, while the Lite HTTP sink has a lower connection
and server-pressure budget.
