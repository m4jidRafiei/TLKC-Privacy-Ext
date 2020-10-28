from p_tlkc_privacy.privacyPreserving import privacyPreserving
import os

event_log = "Sepsis Cases - Event Log.xes"
# event_log = "running_example.xes"

L = [4]
C = [1]
K = [30]
K2 = [0.7]
# sensitive = ['creator']
sensitive = []
T = ["minutes"]
cont = []
bk_type = "sequence" #set, multiset, sequence
time_based = True
trace_attributes = ['concept:name', 'org:group']
life_cycle = ['complete', '']

if not os.path.exists("./xes_results"):
    os.makedirs("./xes_results")

privacy_aware_log_dir = "xes_results"
privacy_aware_log_path = "Sepsis Cases - Event Log - anon.xes"

pp = privacyPreserving(event_log, "Sepsis Cases")
result = pp.apply(T, L, K, C, K2, sensitive, cont, bk_type, trace_attributes, life_cycle, time_based, privacy_aware_log_dir, privacy_aware_log_path)

print(result)