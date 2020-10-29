from p_tlkc_privacy.privacyPreserving import privacyPreserving
import sys
import os

# event_log = "Sepsis Cases - Event Log.xes"
event_log = "Sepsis Cases - Event Log.xes"
# event_log = "running_example.xes"

L = [5]
C = [1]
K = [20]
K2 = [0.8]
# sensitive = ['Diagnose']
sensitive = []
T = ["minutes"]
cont = []
bk_type = "sequence" #set, multiset, sequence
time_based = False
#'lifecycle:transition'
trace_attributes = ['concept:name']
#these life cycles are applied only when all_lif_cycle = False
life_cycle = ['complete', '', 'COMPLETE']
#when life cycle is in trace attributes then all_life_cycle has to be True
all_life_cycle = True


if bk_type != 'sequence' and time_based:
     print("Time is only valid with the sequence type")
     sys.exit(0)


if not os.path.exists("./xes_results"):
    os.makedirs("./xes_results")

privacy_aware_log_dir = "xes_results"
privacy_aware_log_path = event_log[:-4] + "_anon.xes"

pp = privacyPreserving(event_log, "Sepsis Cases")
result = pp.apply(T, L, K, C, K2, sensitive, cont, bk_type, trace_attributes, life_cycle, all_life_cycle,time_based, privacy_aware_log_dir, privacy_aware_log_path)

print(result)