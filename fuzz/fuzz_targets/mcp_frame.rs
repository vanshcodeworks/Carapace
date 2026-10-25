//! TODO(C7-integration): MCP frame fuzzer — depends on the carapace-mcp
//! request parser landing (being built in parallel). Target shape:
//! feed arbitrary bytes as one JSON-RPC line into the parser; assert it
//! never panics and only ever emits valid responses or documented error
//! codes (-32700/-32600/-32601/-32602). Remove this placeholder when the
//! real target lands.
