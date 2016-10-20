#!/bin/sh
.stack-work/install/x86_64-linux/lts-7.2/8.0.1/bin/bench --output out-bench.html > /dev/null
scp out-bench.html karshan.me:~/warp/bench.html
