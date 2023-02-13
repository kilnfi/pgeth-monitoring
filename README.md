# pgeth-monitoring plugin

Runs custom tracers while simulating all transactions, encode and feed everything to redis with topics making things easy to subscribe.

```
/head/tx/0x25b71b769488d271f9be0381d804ceaf0898b1a476da540f70196b166e0e1017/0x94232B820E820750B391C585D4456D87Db6512Bd/0x1A0C896b84d2085944696076430c06A1f6984172/I@0x1A0C896b84d2085944696076430c06A1f6984172[D@0x6bf5ed59dE0E19999d264746843FF931c0133090[C@0x1dE06D2875453a272628BbB957077d18eb4A84CD]]
```

The topics follow the following format

```
/CHANNEL/tx/TX_HASH/FROM/TO/CALL_TRACES
```

Where the example above call traces can be interpreted as:

```
I@0x1A0C896b84d2085944696076430c06A1f6984172[D@0x6bf5ed59dE0E19999d264746843FF931c0133090[C@0x1dE06D2875453a272628BbB957077d18eb4A84CD]]

I@0x1A0C896b84d2085944696076430c06A1f6984172[
  D@0x6bf5ed59dE0E19999d264746843FF931c0133090[
    C@0x1dE06D2875453a272628BbB957077d18eb4A84CD
  ]
]
```

- Initial (`I`) call made to `0x1A0C896b84d2085944696076430c06A1f6984172`
- `0x1A0C896b84d2085944696076430c06A1f6984172` then performs a `delegatecall` (`D`) to `0x6bf5ed59dE0E19999d264746843FF931c0133090`
- Then, with the code at `0x6bf5ed59dE0E19999d264746843FF931c0133090` but still in `0x1A0C896b84d2085944696076430c06A1f6984172`'s context (due to the nature of delegatecall), at regular `call` (`C`) is made to `0x1dE06D2875453a272628BbB957077d18eb4A84CD`

The different call modes are 

- `I`, the initial call
- `C`, a regular `call`
- `S`, a `staticcall`
- `D`, a `delegatecall`

The message payload will provide complete execution details with inputs, outputs, context and code address for every step
