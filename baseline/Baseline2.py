import math
import datetime
from pm4py.objects.log.log import EventLog


class Baseline2:

    def __init__(self, log, sensitive, k,t):
        self.log = log
        self.sensitive = sensitive
        self.k = k
        self.t = t

    def simplify_without_time_count(self):
        concept = ["concept:name"]
        time = ['time:timestamp']
        logsimple = {}
        traces = []
        sensitives = {el: [] for el in self.sensitive}
        for case_index, case in enumerate(self.log):
            # as cache for each case
            sens = {}
            trace = []
            c = []
            for event_index, event in enumerate(case):
                # basis for tuple of (event,time)
                pair = [[], []]
                for key, value in event.items():
                    if key in concept:
                        pair[0] = value
                    elif key in self.sensitive:
                        # sample all sensitive values for one trace in sens
                        sens[key] = value
                #pair of event, occurence
                count_el = c.count(pair[0])
                tu = (pair[0], count_el + 1)
                c.append(pair[0])
                # create trace with pairs (event,time)
                trace.append(tu)
            #create simplified log
            logsimple[case.attributes["concept:name"]] = {"trace": trace, "sensitive": sens}
            # list with all traces without CaseID
            traces.append(trace)
            # sample all values for a specific sensitive attribute (key) in dict
            for key in sens.keys():
               # sample all values for a specific sensitive attribute (key) in dict
                sensitives[key].append(sens[key])
        return logsimple, traces, sensitives

#trace1 is problem trace
    def distance(self, trace1, trace2):
        mismatch = 0
        mis_el = []
        index = 0
        i = 0
        j = 0
        #trace2 is shorter
        while j < len(trace2) and i < len(trace1):
            if trace1[i] != trace2[j]:
                if trace1[i] not in trace2:
                    mismatch += 1
                    mis_el.append(trace1[i])
                    i += 1
                else:
                    mismatch = math.inf
                    i = len(trace1) + 2
                    j = len(trace2) + 2
            else:
                i += 1
                j += 1
        for i2 in range(i,len(trace1)):
            mismatch += 1
            mis_el.append(trace1[i2])
        for j2 in range(j, len(trace2)):
            mismatch += 1
        return mismatch

    def get_variants_with_count(self, logsimple):
        dict_variant = {tuple(var): [] for var in [logsimple[key]["trace"] for key in logsimple.keys()]}
        dict_count = {tuple(var): 0 for var in [logsimple[key]["trace"] for key in logsimple.keys()]}
        for key in list(logsimple.keys()):
            dict_variant[tuple(logsimple[key]["trace"])].append(key)
            dict_count[tuple(logsimple[key]["trace"])] += 1
        variants = list(dict_variant.keys())
        return variants,dict_variant,dict_count

    def suppress_k_annonymity(self):
        logsimple,traces,sensitives = self.simplify_without_time_count()
        variants,dict_variant, dict_count = self.get_variants_with_count(logsimple)
        prob = min(dict_count, key=dict_count.get)
        while dict_count[tuple(prob)] < self.k:
            dist = math.inf
            var = prob
            candidates = [el for el in variants if len(el) < len(prob) and all(el2 in prob for el2 in el)]
            if candidates != []:
                for v in candidates:
                    dist2 = self.distance(prob,v)
                    if dist2 == 0:
                        print(v)
                        print(prob)
                    if dist2 < dist:
                        dist = dist2
                        var = v
                if dist != math.inf:
                    for key in dict_variant[tuple(prob)]:
                        logsimple[key]["trace"] = var
                else:
                    for key in dict_variant[tuple(prob)]:
                        del logsimple[key]
            else:
                for key in dict_variant[tuple(prob)]:
                    del logsimple[key]
            variants, dict_variant, dict_count = self.get_variants_with_count(logsimple)
            prob = min(dict_count, key=dict_count.get)
        log, d, d_l = self.createEventLog(logsimple)
        return log, d, d_l

    def createEventLog(self, simplifiedlog):
        deleteLog = []
        log = self.log
        d = 0
        d_l = 0
        spectime = self.t
        for i in range(0, len(log)):
            caseId = log[i].attributes["concept:name"]
            if caseId not in simplifiedlog.keys():
                deleteLog.append(i)
                continue
            trace = simplifiedlog[caseId]["trace"]
            k = 0
            j = 0
            while j < len(log[i]) and k < len(trace):
                if trace[k][0] == log[i][j]["concept:name"]:
                    if spectime == "seconds":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                            hour=0, minute=0, second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            hours = int(sectim / 3600)
                            sectim = sectim - hours * 3600
                            minutes = int(sectim / 60)
                            sectim = sectim - minutes * 60
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                            day=1 + days, hour=hours,
                                                                            minute=minutes, second=sectim)
                    elif spectime == "minutes":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                            hour=0, minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            hours = int(sectim / 3600)
                            sectim = sectim - hours * 3600
                            minutes = int(sectim / 60)
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                            day=1 + days, hour=hours,
                                                                            minute=minutes,second=0)
                    elif spectime == "hours":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                            hour=0,minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            hours = int(sectim / 3600)
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                            day=1 + days, hour=hours,minute=0,second=0)
                    k += 1
                    j += 1
                else:
                    log[i]._list.remove(log[i][j])
                    d += 1
            if j < len(log[i]):
                for k in range(len(log[i])-1, j - 1 ,-1):
                    log[i]._list.remove(log[i][k])
                    d += 1
                    j += 1
            if len(log[i]) == 0:
                deleteLog.append(i)
        for i in sorted(deleteLog, reverse=True):
            log._list.remove(log[i])
            d_l += 1
        log2 = EventLog([trace for trace in log])
        return log2, d, d_l

    def month_translate(self, daystime):
        if daystime <= 30:
            month = 0
            days = daystime
        elif daystime <= 58:
            month = 1
            days = daystime - 30
        elif daystime <= 89:
            month = 2
            days = daystime - 58
        elif daystime <= 119:
            month = 3
            days = daystime - 89
        elif daystime <= 150:
            month = 4
            days = daystime - 119
        elif daystime <= 180:
            month = 5
            days = daystime - 150
        elif daystime <= 211:
            month = 6
            days = daystime - 180
        elif daystime <= 242:
            month = 7
            days = daystime - 211
        elif daystime <= 273:
            month = 8
            days = daystime - 242
        elif daystime <= 303:
            month = 9
            days = daystime - 273
        elif daystime <= 334:
            month = 10
            days = daystime - 303
        elif daystime <= 365:
            month = 11
            days = daystime - 334
        if days != 0:
            days -= 1
        return month, days