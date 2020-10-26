# Input: Raw trajectory data table T
# Input: Thresholds L, K, and C
# Input: Sensitive values sensitive
#Input: logsimple (dict) gives all traces in combination with sensitive values
#Input: cont (list) gives which sensitive attributes are cont
#Output: violating (list) all minimal violating subtraces
import numpy as np
import operator
class MVS():

    def __init__(self, T, logsimple, sensitive, cont, sensitives, count=False, set1=False, dict_safe={}):
        self.T = T
        self.logsimple = logsimple
        self.sensitive = sensitive
        self.cont = cont
        self.sensitives = sensitives
        self.dev = []
        self.count = count
        self.set = set1
        self.dict_safe = dict_safe


    def mvs(self, L, K, C,k2,t = None):
        i = L
        while i > 0 and i < L + 1:
            i -= 1
            if t is None:
                if self.dict_safe[i][K][C][k2]["v"] != []:
                    w = self.dict_safe[i][K][C][k2]["w"]
                    X1 = self.dict_safe[i][K][C][k2]["x"]
                    violating = self.dict_safe[i][K][C][k2]["v"]
            else:
                if self.dict_safe[i][K][C][t][k2]["v"] != []:
                    w = self.dict_safe[i][K][C][t][k2]["w"]
                    X1 = self.dict_safe[i][K][C][t][k2]["x"]
                    violating = self.dict_safe[i][K][C][t][k2]["v"]
            if 'X1' in locals() and len(X1) > 0:
                count = {tuple(el): 0 for el in X1}
                prob = {tuple(v): {el: [] for el in self.sensitive} for v in X1}
                el_trace = {tuple(el): [] for el in X1}
                i += 1
                w.append([])
                violating.append([])
                prob, count, el_trace = self.prob(X1, count, el_trace, prob, i, type, first=True)
                gen = [q for q in X1 if count[tuple(q)] > 0]
                w, violating = self.w_violating(gen, count, violating, prob, K, C, w, i)
                # 10: end if
                # 11: end for
                X1.clear()
                # 12: Xi+1 ! Wi ! Wi;
                X1 = self.w_create(w, i, X1, violating)
                print("X1: " + str(len(X1)))
                i += 1
                break
            elif 'X1' in locals() and len(X1) == 0:
                i = L+1
        # 1: X1 <- set of all distinct pairs in T;
        if i == 0:
            flat_list = [item for sublist in self.T for item in sublist]
            X1 = list(set(flat_list))
            # 2: i = 1;
            #count(q)
            #prob(q|s)
            count = {el: 0 for el in X1}
            prob = {v: {el: [] for el in self.sensitive} for v in X1}
            el_trace = {el: [] for el in X1}
            prob, count, el_trace = self.prob(X1, count, el_trace, prob, i, type)
            # 5: for all q  in Xi where |T(q)| > 0 do
            gen = [q for q in X1 if count[tuple(q)] > 0]
            violating = [[]]
            w = [[]]
            w, violating = self.w_violating(gen, count, violating, prob, K, C, w, i)
            # 10: end if
            # 11: end for
            w[0].sort(key=operator.itemgetter(1))
            X1.clear()
            # 12: Xi+1 ! Wi ! Wi;
            if not self.set and not self.count:
                while len(w[0]) > 1:
                    candidate = w[0].pop(0)
                    for comb in w[0]:
                        if comb[1] > candidate[1]:
                            X1.append([candidate, comb])
                        elif comb[0] != candidate[0] and comb[1] == candidate[1]:
                            X1.append([candidate, comb])
                        elif comb[1] < candidate[1]:
                            X1.append([comb, candidate])
            elif not self.set and self.count:
                while len(w[0]) > 1:
                    candidate = w[0].pop(0)
                    for comb in w[0]:
                        if comb[0] != candidate[0]:
                            X1.append([candidate, comb])
                        elif comb[1] > candidate[1]:
                            X1.append([candidate, comb])
                        elif comb[1] < candidate[1]:
                            X1.append([comb, candidate])
            elif self.set and not self.count:
                while len(w[0]) > 1:
                    candidate = w[0].pop(0)
                    for comb in w[0]:
                        if sorted([candidate, comb]) not in X1:
                            X1.append(sorted([candidate, comb]))
            elif self.set and self.count:
                while len(w[0]) > 1:
                    candidate = w[0].pop(0)
                    for comb in w[0]:
                        if sorted([candidate, comb]) not in X1:
                            if comb[0] != candidate[0]:
                                X1.append(sorted([candidate, comb]))
                            elif comb[0] == candidate[0] and comb[1] != candidate[1]:
                                X1.append(sorted([candidate, comb]))

            # elif self.set and self.count:
            #     while len(w[0]) > 1:
            #         candidate = w[0].pop(0)
            #         for comb in w[0]:
            #             if sorted([candidate, comb]) not in X1:
            #                 if comb[0] != candidate[0]:
            #                     #more checks ----- if the candidate possible based on event log
            #                     for key,process_instance in self.logsimple.items():
            #                         if(self.sublist(process_instance['trace'],sorted([candidate, comb]))):
            #                             X1.append(sorted([candidate, comb]))
            #                             break
            #                 elif comb[0] == candidate[0] and comb[1] != candidate[1]:
            #                     for key,process_instance in self.logsimple.items():
            #                         if(self.sublist(process_instance['trace'],sorted([candidate, comb]))):
            #                             X1.append(sorted([candidate, comb]))
            #                             break


            # 13: for %q & Xi+1 do
            # should not be necessary for first round
            # 15: Remove q from Xi+1;
            # 16: end if
            # 17: end for
            i = 1
            print("X1: " + str(len(X1)))
        # 3: while i <= L or Xi not empty do
        while i < L and len(X1) > 0:
            # 4: Scan T to compute |T(q)| and P(s|q), for all q in Xi, for all s in S;
            w.append([])
            violating.append([])
            count = {tuple(el): 0 for el in X1}
            prob = {tuple(v): {el: [] for el in self.sensitive} for v in X1}
            prob, count, el_trace = self.prob(X1, count, el_trace, prob, i, type)
            # 5: for all q  in Xi where |T(q)| > 0 do
            gen = [q for q in X1 if count[tuple(q)] > 0]
            w, violating = self.w_violating(gen, count, violating, prob, K, C, w, i)
            # 10: end if
            # 11: end for
            X1.clear()
            # 12: Xi+1 ! Wi ! Wi;
            X1 = self.w_create(w, i, X1, violating)
            print("X1: " + str(len(X1)))
            # 18: i++;
            i += 1
        # 19: end while
        # 20: return V (T) = V1 ' · · · ' Vi−1;
        if t is None:
            self.dict_safe[i - 1][K][C][k2]["w"] = w.copy()
            self.dict_safe[i - 1][K][C][k2]["x"] = X1.copy()
            self.dict_safe[i - 1][K][C][k2]["v"] = violating.copy()
        else:
            self.dict_safe[i - 1][K][C][t][k2]["w"] = w.copy()
            self.dict_safe[i - 1][K][C][t][k2]["x"] = X1.copy()
            self.dict_safe[i - 1][K][C][t][k2]["v"] = violating.copy()
        violatingConj = [item for sublist in violating for item in sublist]
        return violatingConj, self.dict_safe


    def w_create(self, w, i, X1, violating):
        if self.count and not self.set:
            while len(w[i]) > 0:
                candidate = w[i].pop()
                for comb in w[i]:
                    add = False
                    add2 = False
                    if candidate[0:i] == comb[0:i] and comb[i][0] != candidate[i][0]:
                        add = True
                    elif candidate[0:i] == comb[0:i] and comb[i][0] == candidate[i][0] \
                            and comb[i][1] > candidate[i][1]:
                        add = True
                    elif candidate[0:i] == comb[0:i] and comb[i][0] == candidate[i][0] \
                            and comb[i][1] < candidate[i][1]:
                        add2 = True
                    if add:
                        X1.append([])
                        X1[len(X1) - 1] = candidate[:]
                        X1[len(X1) - 1].append(comb[i])
                    elif add2:
                        X1.append([])
                        X1[len(X1) - 1] = comb[:]
                        X1[len(X1) - 1].append(candidate[i])
                    if add or add2:
                        if X1[len(X1) - 1] in X1[0:len(X1) - 1]:
                            del X1[-1]
                        else:
                            # 13: for %q & Xi+1 do
                            # 14: if q is a super sequence of any v & Vi then
                            # 15: Remove q from Xi+1;
                            if len(X1) == 0:
                                break
                            included = False
                            for v in violating[i]:
                                if all(elem in X1[len(X1) - 1] for elem in v):
                                    for j in range(0, i + 1):
                                        if j == 0:
                                            if v[j] in X1[len(X1) - 1]:
                                                index = X1[len(X1) - 1].index(v[j])
                                            else:
                                                break
                                        else:
                                            if v[j] in X1[len(X1) - 1][index + 1::]:
                                                index = X1[len(X1) - 1].index(v[j])
                                                if j == i:
                                                    included = True
                                                    break
                                            else:
                                                break
                                # if all(elem in X1[len(X1) - 1] for elem in v):
                                if included:
                                    del X1[-1]
                                    break

        elif self.set and self.count:
            while len(w[i]) > 0:
                candidate = w[i].pop()
                for comb in w[i]:
                    if candidate[0:i] == comb[0:i] and comb[i] not in candidate:
                        X1.append([])
                        X1[len(X1) - 1] = candidate[:]
                        X1[len(X1) - 1].append(comb[i])
                        X1[len(X1) - 1] = sorted(X1[len(X1) - 1])
                        if X1[len(X1) - 1] in X1[0:len(X1) - 1]:
                            del X1[-1]
                        else:
                            # 13: for %q & Xi+1 do
                            # 14: if q is a super sequence of any v & Vi then
                            # 15: Remove q from Xi+1;
                            for v in violating[i]:
                                if len(X1) == 0:
                                    break
                                if all(elem in X1[len(X1) - 1] for elem in v):
                                    del X1[-1]
        elif self.set and not self.count:
            while len(w[i])>0:
                candidate = w[i].pop()
                for comb in w[i]:
                    if candidate[0:i] == comb[0:i] and comb[i] not in candidate:
                        X1.append([])
                        X1[len(X1) - 1] = candidate[:]
                        X1[len(X1) - 1].append(comb[i])
                        X1[len(X1) - 1] = sorted(X1[len(X1) - 1])
                        if X1[len(X1) - 1] in X1[0:len(X1) - 1]:
                            del X1[-1]
                        else:
                            # 13: for %q & Xi+1 do
                            # 14: if q is a super sequence of any v & Vi then
                            # 15: Remove q from Xi+1;
                            for v in violating[i]:
                                if len(X1) == 0:
                                    break
                                if all(elem in X1[len(X1) - 1] for elem in v):
                                    del X1[-1]

        # elif self.set and self.count:
        #     while len(w[i]) > 0:
        #         candidate = w[i].pop()
        #         for comb in w[i]:
        #             if candidate[0:i] == comb[0:i] and comb[i] not in candidate:
        #                 new_element = candidate.copy()
        #                 new_element.append(comb[i])
        #                 # more checks ----- if the candidate possible based on event log
        #                 for key, process_instance in self.logsimple.items():
        #                     if (self.sublist(process_instance['trace'], sorted(new_element))):
        #                         X1.append([])
        #                         X1[len(X1) - 1] = candidate[:]
        #                         X1[len(X1) - 1].append(comb[i])
        #                         X1[len(X1) - 1] = sorted(X1[len(X1) - 1])
        #                         if X1[len(X1) - 1] in X1[0:len(X1) - 1]:
        #                             del X1[-1]
        #                         else:
        #                             # 13: for %q & Xi+1 do
        #                             # 14: if q is a super sequence of any v & Vi then
        #                             # 15: Remove q from Xi+1;
        #                             for v in violating[i]:
        #                                 if len(X1) == 0:
        #                                     break
        #                                 if all(elem in X1[len(X1) - 1] for elem in v):
        #                                     del X1[-1]
        #                         break
        else:
            while len(w[i]) > 0:
                candidate = w[i].pop()
                for comb in w[i]:
                    if candidate[0:i] == comb[0:i] and candidate[i][1] > comb[i][1]:
                        X1.append([])
                        X1[len(X1) - 1] = comb[:]
                        X1[len(X1) - 1].append(candidate[i])
                    elif candidate[0:i] == comb[0:i] and candidate[i][1] < comb[i][1]:
                        X1.append([])
                        X1[len(X1) - 1] = candidate[:]
                        X1[len(X1) - 1].append(comb[i])
                    elif candidate[0:i] == comb[0:i] and candidate[i][1] == comb[i][1] and candidate[i][1] != comb[i][1]:
                        X1.append([])
                        X1[len(X1) - 1] = candidate[:]
                        X1[len(X1) - 1].append(comb[i])
                    else:
                        break
                    if X1[len(X1) - 1] in X1[0:len(X1) - 1]:
                        del X1[-1]
                    else:
                        # 13: for %q & Xi+1 do
                        # 14: if q is a super sequence of any v & Vi then
                        # 15: Remove q from Xi+1;
                        included = False
                        for v in violating[i]:
                            if len(X1) == 0:
                                break
                            if all(elem in X1[len(X1) - 1] for elem in v):
                                for j in range(0, i + 1):
                                    if j == 0:
                                        if v[j] in X1[len(X1) - 1]:
                                            index = X1[len(X1) - 1].index(v[j])
                                        else:
                                            break
                                    else:
                                        if v[j] in X1[len(X1) - 1][index + 1::]:
                                            index = X1[len(X1) - 1].index(v[j])
                                            if j == i:
                                                included = True
                                                break
                                        else:
                                            break
                            # if all(elem in X1[len(X1) - 1] for elem in v):
                            if included:
                                del X1[-1]
                                break
        return X1

    def w_violating(self,gen,count,violating,prob, K,C,w, i):
        if i == 0:
            for q in gen:
                # 6: if |T(q)|< K or P(s|q) > C then
                if count[q] < K:
                    violating[0].append([q])
                else:
                    highestC = 0
                    for s in self.sensitive:
                        if highestC > C:
                            break
                        if prob[q][s] > highestC:
                            highestC = prob[q][s]
                    # 7: Add q to Vi;
                    if highestC > C:
                        violating[0].append([q])
                    # 8: else
                    # 9: Add q to Wi;
                    else:
                        w[0].append(q)
        else:
            for q in gen:
                # 6: if |T(q)|< K or P(s|q) > C then
                if count[tuple(q)] < K:
                    violating[i].append(q)
                else:
                    highestC = 0
                    for s in self.sensitive:
                        if highestC > C:
                            break
                        if prob[tuple(q)][s] > highestC:
                            highestC = prob[tuple(q)][s]
                    # 7: Add q to Vi;
                    if highestC > C:
                        violating[i].append(q)
                    # 8: else
                    # 9: Add q to Wi;
                    else:
                        w[i].append(q)
        return w, violating

    def prob(self, X1, count, el_trace, prob, i, type,first=False):
        if first:
            for q in X1:
              #creating prob(q|s) and count(q)
                for key, value in self.logsimple.items():
                    tr = value["trace"]
                    S = value["sensitive"]
                    if self.set:
                        if all(elem in tr for elem in q):
                            count[tuple(q)] += 1
                            el_trace[tuple(q)].append(value)
                            #listing all values of the different sensitive attributes (key2)
                            for key2, value2 in S.items():
                                prob[tuple(q)][key2].append(value2)
                    else:
                        included = False
                        for j in range(0, len(q)):
                            if j == 0:
                                if q[j] in tr:
                                    index = tr.index(q[j])
                                else:
                                    break
                            else:
                                if q[j] in tr[index + 1::]:
                                    index = tr.index(q[j])
                                    if j == len(q) - 1:
                                        included = True
                                        break
                                else:
                                    break
                            # if all(elem in X1[len(X1) - 1] for elem in v):
                        if included:
                            count[tuple(q)] += 1
                            el_trace[tuple(q)].append(value)
                            # listing all values of the different sensitive attributes (key2)
                            for key2, value2 in S.items():
                                prob[tuple(q)][key2].append(value2)
                #calculating the distribution of s for q
            for q in X1:
                prob = self.sens_boxplot(prob, count, q, i)
        else:
            if i == 0:
                for key, value in self.logsimple.items():
                  #creating prob(q|s) and count(q)
                    for q in X1:
                        tr = value["trace"]
                        S = value["sensitive"]
                        if q in tr:
                            count[q] += 1
                            el_trace[q].append(value)
                            #listing all values of the different sensitive attributes (key2)
                            for key2, value2 in S.items():
                                prob[q][key2].append(value2)
                    #calculating the distribution of s for q
                for q in X1:
                    prob = self.sens_boxplot(prob, count, q, i)
            else:
                newel_trace = {tuple(el): [] for el in X1}
                if not self.set:
                    for q in X1:
                        if len(q) == 2:
                            for value in el_trace[q[0]]:
                                tr = value["trace"]
                                S = value["sensitive"]
                                included = True
                                if self.count:
                                    if q[i] not in tr[tr.index(q[0])+1::]:
                                        included = False
                                else:
                                    if q[i] not in tr:
                                        included = False
                                if included:
                                    count[tuple(q)] += 1
                                    newel_trace[tuple(q)].append(value.copy())
                                    for key2, value2 in S.items():
                                        prob[tuple(q)][key2].append(value2)
                        else:
                            # if tuple(q[0:i]) not in el_trace.keys():
                            #     print(el_trace)
                            # else:
                            for value in el_trace[tuple(q[0:i])]:
                                tr = value["trace"]
                                S = value["sensitive"]
                                included = True
                                if self.count:
                                    #if something went wrong
                                    if q[i-1] not in tr:
                                        included = False
                                    elif q[i] not in tr[tr.index(q[i-1]) + 1::]:
                                        included = False
                                else:
                                    if q[i] not in tr:
                                        included = False
                                if included:
                                    count[tuple(q)] += 1
                                    newel_trace[tuple(q)].append(value.copy())
                                    for key2, value2 in S.items():
                                        prob[tuple(q)][key2].append(value2)
                        prob = self.sens_boxplot(prob, count, q, i)
                else:
                    for key, value in self.logsimple.items():
                        for q in X1:
                            if len(q) == 2:
                                tr = value["trace"]
                                S = value["sensitive"]
                                included = True
                                for j in range(0,len(q)):
                                    if q[j] not in tr:
                                        included = False
                                        break
                                if included:
                                    count[tuple(q)] += 1
                                    newel_trace[tuple(q)].append(value.copy())
                                    for key2, value2 in S.items():
                                        prob[tuple(q)][key2].append(value2)
                            else:
                                tr = value["trace"]
                                S = value["sensitive"]
                                included = True
                                for j in range(0, len(q)):
                                    if q[j] not in tr:
                                        included = False
                                        break
                                if included:
                                    count[tuple(q)] += 1
                                    newel_trace[tuple(q)].append(value.copy())
                                    for key2, value2 in S.items():
                                        prob[tuple(q)][key2].append(value2)
                    for q in X1:
                        prob = self.sens_boxplot(prob, count, q, i)
                el_trace = newel_trace.copy()
        return prob, count, el_trace

    def sens_boxplot(self, prob, count, q, i):
        if i == 0:
            # calculating the distribution of s for q
            for key in self.sensitive:
                highest = 0
                if key in self.cont:
                    freq = {"low": 0, "middle": 0, "high": 0}
                    lower_quartile = np.percentile(prob[q][key], 25)
                    higher_quartile = np.percentile(prob[q][key], 75)
                else:
                    freq = {v: 0 for v in prob[q][key]}
                for item in prob[q][key]:
                    # continious variables are handled with standard deviation
                    if key in self.cont:
                        if item < lower_quartile:
                            freq["low"] += 1
                        elif item > higher_quartile:
                            freq["high"] += 1
                        else:
                            freq["middle"] += 1
                    else:
                        if item in freq:
                            freq[item] += 1
                        else:
                            freq[item] = 1
                # Calculate confidence (C) which is mean of the category confidences,
                # where confidence of each category is 1/(No. values in the category).
                if key in self.cont:
                    if freq["low"] > 0:
                        low = 1 / freq["low"]
                    else:
                        low = 0
                    if freq["middle"] > 0:
                        middle = 1 / freq["middle"]
                    else:
                        middle = 0
                    if freq["high"]:
                        high = 1 / freq["high"]
                    else:
                        high = 0
                    highest = (low + middle + high) / 3
                else:
                    for item in prob[q][key]:
                        newhighest = freq[item] / count[q]
                        if newhighest > highest:
                            highest = newhighest
                prob[q][key] = highest
        else:
            for key in self.sensitive:
                highest = 0
                if prob[tuple(q)][key] == []:
                    prob[tuple(q)][key] = 0
                    continue
                if key in self.cont:
                    freq = {"low": 0, "middle": 0, "high": 0}
                    lower_quartile = np.percentile(prob[tuple(q)][key], 25)
                    higher_quartile = np.percentile(prob[tuple(q)][key], 75)
                else:
                    freq = {v: 0 for v in prob[tuple(q)][key]}
                for item in prob[tuple(q)][key]:
                    # continious variables are handled with standard deviation
                    if key in self.cont:
                        if item < lower_quartile:
                            freq["low"] += 1
                        elif item > higher_quartile:
                            freq["high"] += 1
                        else:
                            freq["middle"] += 1
                    else:
                        if item in freq:
                            freq[item] += 1
                        else:
                            freq[item] = 1
                # Calculate confidence (C) which is mean of the category confidences,
                # where confidence of each category is 1/(No. values in the category).
                if key in self.cont:
                    if freq["low"] > 0:
                        low = 1 / freq["low"]
                    else:
                        low = 0
                    if freq["middle"] > 0:
                        middle = 1 / freq["middle"]
                    else:
                        middle = 0
                    if freq["high"]:
                        high = 1 / freq["high"]
                    else:
                        high = 0
                    highest = (low + middle + high) / 3
                else:
                    for item in prob[tuple(q)][key]:
                        newhighest = freq[item] / count[tuple(q)]
                        if newhighest > highest:
                            highest = newhighest
                prob[tuple(q)][key] = highest
        return prob
