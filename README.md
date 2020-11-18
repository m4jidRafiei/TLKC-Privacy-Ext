## Introduction
This project implements the extended version of the TLKC-privacy model proposed in the paper [TLKC-Privacy Model for Process Mining](https://www.researchgate.net/publication/340261780_TLKC-Privacy_Model_for_Process_Mining).

## Usage

```python
from p_tlkc_privacy.privacyPreserving import privacyPreserving
import os

event_log = "running_example.xes"

L = [3]
C = [1]
K = [10]
K2 = [0.0] # not used anymore
alpha = 0.5 #privacy coefficent
beta = 0.5 #utility coefficent
sensitive = []
T = ["minutes"]
cont = []
bk_type = "relative" #set, multiset, sequence, relative
trace_attributes = ['concept:name']
life_cycle = ['complete', '', 'COMPLETE'] #these life cycles are applied only when all_lif_cycle = False
all_life_cycle = True #when life cycle is in trace attributes then all_life_cycle has to be True

if not os.path.exists("./xes_results"):
    os.makedirs("./xes_results")

privacy_aware_log_dir = "xes_results"
privacy_aware_log_path = event_log[:-4] + "_anon.xes"

pp = privacyPreserving(event_log, "Sepsis Cases")
result = pp.apply(T, L, K, C, K2, sensitive, cont, bk_type, trace_attributes, life_cycle, all_life_cycle, privacy_aware_log_dir, privacy_aware_log_path,alpha, beta)

print(result)
```
