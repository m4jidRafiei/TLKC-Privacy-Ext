from p_tlkc_privacy.privacyPreserving import privacyPreserving
import os

event_log = "Sepsis Cases - Event Log.xes"

L = [8]
C = [1]
K = [200]
K2 = [0.9]
# sensitive = ['creator']
sensitive = []
T = ["seconds"]
cont = []
bk_type = "set" #set, multiset, sequence, relative

if not os.path.exists("./xes_results"):
    os.makedirs("./xes_results")

privacy_aware_log_dir = "xes_results"
privacy_aware_log_path = "Sepsis Cases - Event Log - anon.xes"

pp = privacyPreserving(event_log, "Sepsis Cases")
result = pp.apply(T, L, K, C, K2, sensitive, cont, bk_type, privacy_aware_log_dir, privacy_aware_log_path)

print(result)

