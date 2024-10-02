### Reproduce error with context

1. Checkout zkwasm using `richard/explorer-2.0-ctx-test`
2. cd into `zkwasm` and run `test_cli.sh` to generate proof using context wasm and inputs.
3. cd into this batcher repo and run `scripts/test_cont.sh` to generate proof using context wasm and inputs.
   - expect error here during aggregation
