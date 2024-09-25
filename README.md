## Reproduce cuda OOM error for auto submit batching

1. Ensure `zkWasm` single proof is generated (I tested using fibonacci and running with continuation feature)

2. Update the dir in `scripts/test_cont.sh` to the correct local zkwasm path

3. run `sh scripts/test_cont.sh` to reproduce the error, it should do aggregate batch(b_1), and then do further aggregation of b_1. It should fail with cuda OOM error.
