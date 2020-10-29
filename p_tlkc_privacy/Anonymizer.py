from p_tlkc_privacy import MFS, ELReps, MVS


class Anonymizer:

    def __init__(self):
        self = self

    def sequence_type(self, log, log2, sensitive,cont,l,k,c,k2,dict1,spectime,trace_attributes, life_cycle,all_life_cycle,time_based,bk_type):
        mfs = MFS.MFS()
        repres = ELReps.ELReps(log)
        logsimple_count, T_count, sensitives_count = repres.create_simple_log(bk_type,trace_attributes,life_cycle, all_life_cycle,sensitive, time_based,time_accuracy='seconds')

        frequent_count = mfs.frequent_seq_activity(T_count, k2 * len(T_count))
        mvs = MVS.MVS(T_count, logsimple_count, sensitive, cont, sensitives_count, bk_type, time_based, dict_safe= dict1)
        violating_count, dict1 = mvs.mvs(l, k, c,k2)
        violating_length = len(violating_count.copy())
        frequent_length = len(frequent_count.copy())
        sup_count = repres.suppression(violating_count, frequent_count)
        T_count = repres.suppressT(logsimple_count.copy(), sup_count)
        log_count = {t: None for t in spectime}
        d_count = {t: None for t in spectime}
        d_l_count = {t: None for t in spectime}
        for t in spectime:
            T_count2 = T_count.copy()
            repres = ELReps.ELReps(log2[t])
            log_count[t], d_count[t], d_l_count[t] = repres.createEventLog(T_count2, t,trace_attributes,life_cycle,all_life_cycle,bk_type,time_based, sensitive, time_accuracy='seconds')
        return log_count, frequent_length, violating_length, d_count, d_l_count, dict1


    def sequence_time_type(self, log, sensitive,cont,t,l,k,c,k2,dict1,trace_attributes, life_cycle,all_life_cycle,time_based,bk_type):
        mfs = MFS.MFS()
        repres = ELReps.ELReps(log)
        logsimple, T, sensitives = repres.create_simple_log(bk_type, trace_attributes, life_cycle, all_life_cycle,sensitive, time_based, time_accuracy=t)

        frequent_time = mfs.frequent_seq_activityTime(T, k2*len(T))
        mvs = MVS.MVS(T, logsimple, sensitive, cont, sensitives, bk_type, time_based, dict_safe= dict1)
        violating_time, dict1 = mvs.mvs(l, k, c,k2,t)
        frequent_length_time = len(frequent_time.copy())
        violating_length_time = len(violating_time.copy())
        sup_time = repres.suppression(violating_time, frequent_time)
        T_time = repres.suppressT(logsimple, sup_time)
        log_time, d_time, d_l_time = repres.createEventLog(T_time, t, trace_attributes,life_cycle,all_life_cycle,bk_type,time_based, sensitive, time_accuracy=t)
        return log_time, frequent_length_time, violating_length_time, d_time, d_l_time, dict1

    def set_type(self, log,log2, sensitive,cont,l,k,c,k2,dict1,spectime,trace_attributes, life_cycle,all_life_cycle,time_based,bk_type):
        mfs = MFS.MFS()
        repres = ELReps.ELReps(log)
        logsimple_set, T_set, sensitives_set = repres.create_simple_log(bk_type, trace_attributes, life_cycle, all_life_cycle,sensitive, time_based,time_accuracy='seconds')

        frequent_set = mfs.frequent_set_miner(T_set, k2)
        mvs = MVS.MVS(T_set, logsimple_set, sensitive, cont, sensitives_set, bk_type, time_based, dict_safe=dict1)

        violating_set,dict1 = mvs.mvs(l, k, c,k2)
        frequent_length_set = len(frequent_set.copy())
        violating_length_set = len(violating_set.copy())
        sup_set = repres.suppression(violating_set, frequent_set)

        T_set = repres.suppressT(logsimple_set, sup_set)

        log_set = {t: None for t in spectime}
        d_set = {t: None for t in spectime}
        d_l_set = {t: None for t in spectime}
        for t in spectime:
            # sup_set2 = sup_set.copy()
            # logsimple_set2 = logsimple_set.copy()
            # repres = ELReps.ELReps(log2[t])
            # log_set[t], d_set[t], d_l_set[t] = repres.suppression2(sup_set2, logsimple_set2, t)
            T_set_2 = T_set.copy()
            repres = ELReps.ELReps(log2[t])
            log_set[t], d_set[t], d_l_set[t] = repres.createEventLog(T_set_2, t,trace_attributes, life_cycle,all_life_cycle,bk_type,time_based, sensitive, time_accuracy='seconds')
        return log_set, frequent_length_set, violating_length_set, d_set, d_l_set, dict1

    def multiset_type(self, log, log2, sensitive,cont,l,k,c,k2,dict1,spectime, trace_attributes, life_cycle,all_life_cycle,time_based,bk_type):
        mfs = MFS.MFS()
        repres = ELReps.ELReps(log)
        logsimple_set_count, T_set_count, sensitives_set_count = repres.create_simple_log(bk_type, trace_attributes, life_cycle,all_life_cycle, sensitive, time_based,time_accuracy='seconds')

        frequent_set_count = mfs.frequent_set_miner(T_set_count, k2)
        mvs = MVS.MVS(T_set_count, logsimple_set_count, sensitive, cont, sensitives_set_count, bk_type, time_based, dict_safe=dict1)

        violating_set_count, dict1 = mvs.mvs(l, k, c,k2)
        frequent_length_set_count = len(frequent_set_count.copy())
        violating_length_set_count = len(violating_set_count.copy())
        sup_set_count = repres.suppression(violating_set_count, frequent_set_count)
        T_set_count = repres.suppressT(logsimple_set_count, sup_set_count)
        log_set_count = {t: None for t in spectime}
        d_set_count = {t: None for t in spectime}
        d_l_set_count = {t: None for t in spectime}
        for t in spectime:
            T_set_count2 = T_set_count.copy()
            repres = ELReps.ELReps(log2[t])
            log_set_count[t], d_set_count[t], d_l_set_count[t] = repres.createEventLog(T_set_count2, t, trace_attributes,life_cycle,all_life_cycle,bk_type,time_based, sensitive, time_accuracy='seconds')
        return log_set_count, frequent_length_set_count, violating_length_set_count, d_set_count, d_l_set_count, dict1
