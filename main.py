from datetime import datetime
from p_tlkc_privacy_ext.privacyPreserving import privacyPreserving
import os

if __name__ == '__main__':
    event_log = "Sepsis-Cases-Case-attributes.xes"
    L = [3]
    K = [5]
    C = [1]
    alpha = 0.5  # privacy coefficent
    beta = 0.5  # utility coefficent
    sensitive_att = []  # categorical sensitive attributes
    T = ["minutes"]  # original, seconds, minutes, hours, days
    cont = []  # numerical sensitive attributes
    bk_type = "set"  # set, multiset, sequence, relative
    event_attributes = ['concept:name']  # to simplify the event log
    life_cycle = ['complete', '', 'COMPLETE']  # these life cycles are applied only when all_lif_cycle = False
    all_life_cycle = True  # when life cycle is in trace attributes then all_life_cycle has to be True
    pa_log_dir = "./xes_results"
    pa_log_name = event_log[:-4]
    multiprocess = True  # if you want to you use multiprocessing
    mp_technique = 'pool'
    if not os.path.exists(pa_log_dir):
        os.makedirs(pa_log_dir)
    pp = privacyPreserving(event_log)
    start = datetime.now()
    privacy_aware_log_dir, max_removed = pp.apply(T, L, K, C, sensitive_att, cont, bk_type, event_attributes, life_cycle, all_life_cycle,
                                   alpha, beta, pa_log_dir, pa_log_name, False, multiprocess=multiprocess, mp_technique=mp_technique)
    end = datetime.now() - start
    print(privacy_aware_log_dir)
    print(end)
