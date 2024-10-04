## Reproduce steps

### Set Env
Assume you are in a clean new folder: "reproduce"
#### For zkwasm folder:
1. `git clone git@github.com:ZhenXunGe/zkWasm.git`
2. `cd zkWasm` and `git checkout -t origin/richard/reproduce-fail`
3. `git submodule init`
4. `git submodule update`
5. `bash test_cli.sh` to generate the proofs

#### For continuation-batcher:
1. go back to HOME folder by `cd ..`
2. `git clone git@github.com:DelphinusLab/continuation-batcher.git`
3. `git checkout -t origin/richard/reproduce-test`
4. `vim scripts/test_cont.sh` to change the WKDIR to point to the zkWasm folder, like '/home/yymone/reproduce/zkWasm`
5. `bash scripts/test_cont.sh`

It can reproduce the issue.


