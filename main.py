from p_tlkc_privacy_ext.privacyPreserving import privacyPreserving
import os

event_log = "running_example.xes"
L = [3]
K = [2]
C = [1]
alpha = 0.5 #privacy coefficent
beta = 0.5 #utility coefficent
sensitive_att = []
T = ["minutes"]
cont = []
bk_type = "relative" #set, multiset, sequence, relative
trace_attributes = ['concept:name']
life_cycle = ['complete', '', 'COMPLETE'] #these life cycles are applied only when all_lif_cycle = False
all_life_cycle = True #when life cycle is in trace attributes then all_life_cycle has to be True
if not os.path.exists("./xes_results"):
    os.makedirs("./xes_results")
pa_log_dir = "xes_results"
pa_log_name = event_log[:-4]

pp = privacyPreserving(event_log)
result = pp.apply(T, L, K, C, sensitive_att, cont, bk_type, trace_attributes, life_cycle, all_life_cycle,alpha, beta, pa_log_dir, pa_log_name, False)

print(result)