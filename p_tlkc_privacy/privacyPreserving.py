from datetime import datetime
from pm4py.objects.log.importer.xes import factory as xes_importer_factory
from pm4py.objects.log.exporter.xes import factory as xes_exporter
from p_privacy_metadata.privacyExtension import privacyExtension
from p_tlkc_privacy import Anonymizer
import os


class privacyPreserving(object):
    '''
    Applying privacy preserving technique
    '''

    def __init__(self, log, log_name):
        '''
        Constructor
        '''
        self.log = xes_importer_factory.apply(log)
        self.log_name = log_name

    def apply(self, T, L, K, C, K2, sensitive, cont, bk_type, trace_attributes, life_cycle, all_life_cycle,time_based, directory, file_path):

        if time_based:
            dict1 = {
            l: {k: {c: {t: {k2: {"w": [], "x": [], "v": []} for k2 in K2} for t in T} for c in C} for k in K}
            for l in range(0, L[len(L) - 1] + 1)}
        else:
            dict1 = {l: {k: {c: {k2: {"w": [], "x": [], "v": []} for k2 in K2} for c in C} for k in K}
                     for l in range(0, L[len(L) - 1] + 1)}

        anonymizer = Anonymizer.Anonymizer()

        now =datetime.now()
        date_time = now.strftime(" %m-%d-%y %H-%M-%S ")
        fixed_name = "TLKC" + date_time + self.log_name + " "
        privacy_aware_log_path = os.path.join(directory,file_path)
        for l in L:
            print("l = " + str(l) + " is running...")
            for k2 in K2:
                for k in K:
                    for c in C:
                        try:
                            if bk_type == "set":
                                print("l = " + str(l) + " type = " + str(bk_type) + " is running...")
                                log2 = {t: None for t in T}
                                for t in T:
                                    log2[t] = self.log
                                log_set, frequent_length_set, violating_length_set, d_set, d_l_set, dict2 = \
                                    anonymizer.set_type(self.log, log2, sensitive, cont, l, k, c, k2, dict1, T, trace_attributes, life_cycle, all_life_cycle,time_based, bk_type)
                                dict1 = dict2
                                for t in T:
                                    self.add_privacy_metadata(log_set[t])
                                    #naming for experiments
                                    privacy_aware_log_path = privacy_aware_log_path[:-4]+"_"+str(t)+"_"+str(l)+"_"+str(k)+"_"+str(c)+"_"+str(k2)+"_"+bk_type+".xes"
                                    xes_exporter.export_log(log_set[t],privacy_aware_log_path)
                                    print(file_path + " has been exported!")
                            elif bk_type == "multiset":
                                print("l = " + str(l) + " type = " + str(bk_type) + " is running...")
                                log2 = {t: None for t in T}
                                for t in T:
                                    log2[t] = self.log
                                log_set_count, frequent_length_set_count, violating_length_set_count, d_set_count, d_l_set_count, dict2 = \
                                    anonymizer.multiset_type(self.log, log2, sensitive, cont, l, k, c, k2, dict1, T, trace_attributes, life_cycle,all_life_cycle,time_based,bk_type)
                                dict1 = dict2
                                for t in T:
                                    self.add_privacy_metadata(log_set_count[t])
                                    # naming for experiments
                                    privacy_aware_log_path = privacy_aware_log_path[:-4] + "_" + str(t) + "_" + str(
                                        l) + "_" + str(k) + "_" + str(c) + "_" + str(k2) + "_" + bk_type + ".xes"
                                    xes_exporter.export_log(log_set_count[t], privacy_aware_log_path)
                                    print(file_path + " has been exported!")
                            elif bk_type == "sequence" and time_based:
                                print("l = " + str(l) + " type = " + str(bk_type) + " is running...")
                                for t in T:
                                    log_time, frequent_length_time, violating_length_time, d_time, d_l_time, dict2 = \
                                        anonymizer.sequence_time_type(self.log, sensitive, cont, t, l, k, c, k2, dict1,trace_attributes, life_cycle,all_life_cycle,time_based,bk_type)
                                    self.add_privacy_metadata(log_time)
                                    # naming for experiments
                                    privacy_aware_log_path = privacy_aware_log_path[:-4] + "_" + str(t) + "_" + str(
                                        l) + "_" + str(k) + "_" + str(c) + "_" + str(k2) + "_" + bk_type + ".xes"
                                    xes_exporter.export_log(log_time, privacy_aware_log_path)
                                    print(file_path + " has been exported!")
                                    dict1 = dict2
                            elif bk_type == "sequence":
                                print("l = " + str(l) + " type = " + str(bk_type) + " is running...")
                                log2 = {t: None for t in T}
                                for t in T:
                                    log2[t] = self.log
                                log_seq_count, frequent_length_seq_count, violating_length_seq_count, d_seq_count, d_l_seq_count, dict2 = \
                                    anonymizer.sequence_type(self.log, log2, sensitive, cont, l, k, c, k2, dict1, T, trace_attributes, life_cycle,all_life_cycle,time_based,bk_type)
                                dict1 = dict2
                                for t in T:
                                    self.add_privacy_metadata(log_seq_count[t])
                                    # naming for experiments
                                    privacy_aware_log_path = privacy_aware_log_path[:-4] + "_" + str(t) + "_" + str(
                                        l) + "_" + str(k) + "_" + str(c) + "_" + str(k2) + "_" + bk_type + ".xes"
                                    xes_exporter.export_log(log_seq_count[t], privacy_aware_log_path)
                                    print(file_path + " has been exported!")
                        except Exception as e:
                            print(e)

        return privacy_aware_log_path

    def add_privacy_metadata(self,log):
        prefix = 'privacy:'
        uri = 'paper_version_uri/privacy.xesext'

        privacy = privacyExtension(log, prefix, uri)
        privacy.set_anonymizer('suppression', 'event', 'event')

