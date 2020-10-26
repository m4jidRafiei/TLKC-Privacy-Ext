import pyfpgrowth
from mlxtend.frequent_patterns import apriori
import pandas as pd
from mlxtend.preprocessing import TransactionEncoder

import operator


class MFS():

    def __init__(self):
        self = self


    def frequent_variants(self, variants, counts, threshold):

        most_freq = []
        for index, count in enumerate(counts):
            if(count >= threshold ):
                most_freq.append(variants[index])

        return most_freq

    def frequent_seq_activityTime(self, T, K):
        patterns = pyfpgrowth.find_frequent_patterns(T, K)
        patterns = sorted(list(patterns.keys()), key=len)
        if len(patterns) > 0:
            frequent = [patterns.pop()]
        else:
            frequent = []
        while len(patterns) > 0:
            candidate = patterns.pop()
            super = True
            for f in frequent:
                if all(elem in f for elem in candidate):
                    super = False
                    break
            if super:
                frequent.append(candidate)
        return frequent

    def frequent_seq_activity(self, T, K):
        patterns = pyfpgrowth.find_frequent_patterns(T, K)
        patterns = sorted(list(patterns.keys()), key=len)
        if len(patterns) > 0:
            frequent = [patterns.pop()]
        else:
            frequent = []
        while len(patterns) > 0:
            candidate = patterns.pop()
            super = True
            for f in frequent:
                if all(elem in f for elem in candidate):
                    super = False
                    break
            if super:
                frequent.append(candidate)
        return frequent

    def frequent_set_miner(self, T, K):
        te = TransactionEncoder()
        te_ary = te.fit(T).transform(T)
        df = pd.DataFrame(te_ary, columns=te.columns_)
        frequent_itemsets = apriori(df, min_support=K, use_colnames=True)
        #convert to list of list
        listofList = []
        for item in list(frequent_itemsets['itemsets']):
            list_item = list(item)
            listofList.append(list_item)
        #we just want to have the biggest sets
        patterns = sorted(list(listofList), key=len)
        if len(patterns) > 0:
            frequent = [patterns.pop()]
        else:
            frequent = []
        while len(patterns) > 0:
            candidate = patterns.pop()
            super = True
            for f in frequent:
                if all(elem in f for elem in candidate):
                    super = False
                    break
            if super:
                frequent.append(candidate)

        return frequent

    def remove_counts(self, T_count):

        for index, seq in enumerate(T_count):
            only_activity = []
            for item in seq:
                item_list = list(item)
                item_list[1] = 0
                item_tuple = tuple(item_list)
                only_activity.append(item_tuple)
            T_count[index] = only_activity

        return T_count

