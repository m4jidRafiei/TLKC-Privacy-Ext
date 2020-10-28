import operator
import datetime
from pm4py.objects.log.log import Trace, EventLog
from pm4py.objects.log.util import sorting
from collections import Counter
from multiset import Multiset

class ELReps():

    def __init__(self, log):
        log = sorting.sort_timestamp(log)
        self.log = log

    def create_simple_log(self, bk_type, trace_attributes, life_cycle, sensitive_attributes, time_based, **keyword_param): #time_accuracy
        #If time_based is true then the background knowledge type have to be sequence
        time_prefix = ['time:timestamp']
        life_cycle_prefix = ['lifecycle:transition']
        logsimple = {}
        traces = []
        sensitives = {el: [] for el in sensitive_attributes}
        for case_index, case in enumerate(self.log):
            # as cache for each case
            sens = {}
            trace = []
            bol = True
            trace_temp = []
            for event_index, event in enumerate(case):
                # basis for tuple of (event,time)
                simple_event = [[], []]
                simple_attr_temp = []
                life_cycle_value = ''
                for key, value in event.items():
                    # Filtering out the needed attributes and create new log out of it
                    # simplify timestamp to timeintervalls as precise as spectime
                    # pair[1] = time
                    if bk_type == 'sequence' and time_based and key in time_prefix:
                        if event_index == 0:
                            starttime = value
                            time = 0
                        else:
                            if keyword_param['time_accuracy'] == "seconds":
                                time = (value - starttime).total_seconds()
                            elif keyword_param['time_accuracy'] == "minutes":
                                time = (value.replace(second=0, microsecond=0)
                                           - starttime.replace(second=0, microsecond=0)).total_seconds() / 60
                            elif keyword_param['time_accuracy'] == "hours":
                                time = (value.replace(minute=0, second=0, microsecond=0)
                                           - starttime.replace(minute=0, second=0, microsecond=0)).total_seconds() / 360
                            elif keyword_param['time_accuracy'] == "days":
                                time = (value.replace(hour=0, minute=0, second=0, microsecond=0)
                                           - starttime.replace(hour=0, minute=0, second=0,
                                                               microsecond=0)).total_seconds() \
                                          / 8640
                    # pair[0] = event
                    if key in trace_attributes:
                        simple_attr_temp.append(value)
                    if key in sensitive_attributes:
                        # sample all sensitive values for one trace in sens
                        sens[key] = value
                    if key in life_cycle_prefix:
                        # sample all sensitive values for one trace in sens
                        life_cycle_value = value
                if life_cycle_value in life_cycle:
                    if len(simple_attr_temp) < 2:
                        simple_event[0] = tuple(simple_attr_temp)[0]
                    else:
                        simple_event[0] = tuple(simple_attr_temp)

                    if bk_type == 'sequence' and time_based:
                        simple_event[1] = time
                        tu = (simple_event[0], simple_event[1])
                        trace.append(tu)

                        # checking if timestamps are the same, then deleting
                        # if len(trace) == 0:
                        #     tu = (simple_event[0], simple_event[1])
                        #     # create trace with pairs (event,time)
                        #     trace.append(tu)
                        # # just adding pair if the timestamp is bigger then the one before
                        # elif simple_event[1] < trace[len(trace) - 1][1]:  #simple_event[0] == trace[len(trace) - 1][0] and simple_event[1] == trace[len(trace) - 1][1]
                        #     bol = False
                        #     break
                        # else:
                        #     tu = (simple_event[0], simple_event[1])
                        #     trace.append(tu)

                    elif bk_type == 'multiset':
                        tu = (simple_event[0])
                        trace_temp.append(simple_event[0])
                        trace.append(tu)

                    elif bk_type == 'sequence': #or bk_type == 'multiset':
                        count_event = trace_temp.count(simple_event[0])
                        simple_event[1] = count_event + 1
                        tu = (simple_event[0], simple_event[1])
                        trace_temp.append(simple_event[0])
                        trace.append(tu)

                    elif bk_type == 'set':
                        simple_event[1] = 0
                        tu = (simple_event[0], simple_event[1])
                        trace.append(tu)

            # create simplified log containing new trace (event,time), sensitive attributes
            # if bk_type == "mult" or bk_type == "set":
            #     logsimple[case.attributes["concept:name"]] = {"trace":  sorted(trace), "sensitive": sens}
            #     traces.append( sorted(trace))
            # else:

            if bk_type == 'multiset':
                trace = self.get_multiset_log(trace)

            logsimple[case.attributes["concept:name"]] = {"trace":  trace, "sensitive": sens}
            traces.append(trace)
            # sample all values for a specific sensitive attribute (key) in dict
            for key in sens.keys():
                # sample all values for a specific sensitive attribute (key) in dict
                sensitives[key].append(sens[key])

        return logsimple, traces, sensitives

    def get_multiset_log(self,alist):
        mult_log = []
        alist_tuple = tuple(alist)
        for s in set(alist):
            count = alist_tuple.count(s)
            tu = (s,count)
            mult_log.append(tu)
        return mult_log

    def get_multiset_log_n(self,alist):
        mult_log = []
        for s in alist:
            mult_log.append(Multiset(s))
        return mult_log

    def suppression(self, violating, frequent):
        sup = []
        X1 = []
        for v in violating + frequent:
            if isinstance(v[0], str):
                X1.append(v)
            else:
                for sub in v:
                    X1.append(sub)
        X1 = list(set(X1))
        score_res, mvsEl, mfsEl = self.score(violating, frequent, X1)
        # while PG table is not empty do
        while len(score_res) > 0:
            # 4: select a pair w that has the highest Score to suppress;
            w = max(score_res.items(), key=operator.itemgetter(1))[0]
            # 5: delete all MVS and MFS containing w from MVS -tree and MFS - tree;
            list_mvs = mvsEl[w]
            for l in list_mvs:
                if l not in violating:
                    print(l)
                    print(violating)
                else:
                    violating.remove(l)
            list_mfs = mfsEl[w]
            for l in list_mfs:
                frequent.remove(l)
            # 6: update the Score(p) if both w and p are contained in the same MVS or MFS;
            X1 = []
            for v in violating + frequent:
                if isinstance(v[0], str):
                    X1.append(v)
                else:
                    for sub in v:
                        X1.append(sub)
            X1 = list(set(X1))
            # 7: remove w from PG Table;
            score_res, mvsEl, mfsEl = self.score(violating, frequent, X1)
            # 8: add w to Sup;
            sup.append(w)
        # 9: end
        return sup

    def score(self,violating, frequent, X1):
        priv = {v: 0 for v in X1}
        ut = {f: 0 for f in X1}
        mvsEle = {v: [] for v in X1}
        mfsEle = {f: [] for f in X1}
        for v in violating:
            if isinstance(v[0], str):
                priv[v] += 1
                mvsEle[v].append(v)
            else:
                for el in v:
                    priv[el] += 1
                    mvsEle[el].append(v)
        for f in frequent:
            if isinstance(f[0], str):
                ut[f] += 1
                mfsEle[f].append(f)
            else:
                for el in f:
                    ut[el] += 1
                    mfsEle[el].append(f)
        score = {el: 0 for el in X1}
        for el in X1:
            score[el] = priv[el] / (ut[el] + 1)
            if score[el] == 0:
                del score[el]
        return score, mvsEle, mfsEle

    def suppressT(self,logsimple, sup):
        for key in logsimple.keys():
            list_trace = logsimple[key]['trace']
            for i in range(len(list_trace)-1, -1, -1):
                sub = list_trace[i]
                if sub in sup:
                    list_trace.remove(sub)
            logsimple[key]['trace'] = list_trace
        return logsimple

    def create_tuple(self,trace,trace_attributes,life_cycle):
        life_cycle_prefix = ['lifecycle:transition']
        trace_tuple = []
        life_cycle_value = ''
        for event_index, event in enumerate(trace):
            # basis for tuple of (event,time)
            simple_event = [[], []]
            simple_attr_temp = []
            for key, value in event.items():
                if key in trace_attributes:
                    simple_attr_temp.append(value)
                if key in life_cycle_prefix:
                    # sample all sensitive values for one trace in sens
                    life_cycle_value = value
            if life_cycle_value in life_cycle:
                if len(simple_attr_temp) < 2:
                    simple_event[0] = tuple(simple_attr_temp)[0]
                else:
                    simple_event[0] = tuple(simple_attr_temp)
                tu = (simple_event[0])
                trace_tuple.append(tu)
        return trace_tuple

    def createEventLog(self, simplifiedlog, spectime, trace_attributes,life_cycle):
        deleteLog = []
        log = self.log
        d = 0
        d_l = 0
        for i in range(0, len(log)):
            caseId = log[i].attributes["concept:name"]
            if caseId not in simplifiedlog.keys():
                deleteLog.append(i)
                continue
            trace = simplifiedlog[caseId]["trace"]
            k = 0
            j = 0
            while j < len(log[i]) and k < len(trace):
                trace_tuple = self.create_tuple(log[i], trace_attributes,life_cycle)
                if trace_tuple[j] in [el[0] for el in trace]:
                    if spectime == "seconds":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
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
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day=1 + days, hour=hours,
                                                                            minute=minutes, second=sectim)
                            except:
                                days = days - 1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours,
                                                                                minute=minutes, second=sectim)

                    elif spectime == "minutes":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
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
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day=1 + days, hour=hours,
                                                                            minute=minutes,second=0)
                            except:
                                days = days - 1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours,
                                                                                minute=minutes, second=0)
                    elif spectime == "hours":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
                                                                            hour=0,minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            hours = int(sectim / 3600)
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                          day=1 + days, hour=hours,minute=0,second=0)
                            except:
                                days = days - 1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours, minute=0,
                                                                                second=0)
                    elif spectime == "days":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
                                                                            hour=0,minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            # days = int(sectim / 3600 * 24)
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day= 1+ days, hour=0,minute=0,second=0)
                            except:
                                days = days -1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=0, minute=0,
                                                                                second=0)
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

    def suppression2(self, sup, simplifiedlog, spectime):
        deleteLog = []
        log_del = self.log
        log = self.log
        d = 0
        d_l = 0
        sup = [el[0] for el in sup]
        for i in range(0, len(log)):
            caseId = log[i].attributes["concept:name"]
            if caseId not in simplifiedlog.keys():
                deleteLog.append(i)
                continue
            j = 0
            del_list =[]
            while j < len(log[i]):
                if simplifiedlog[caseId]['trace'][j][0] not in sup:
                    if spectime == "seconds":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
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
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day=1+days, hour=hours,
                                                                            minute=minutes, second=sectim)
                            except:
                                days = days -1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours,
                                                                                minute=minutes, second=sectim)
                    elif spectime == "minutes":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
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
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day=1 + days, hour=hours,
                                                                            minute=minutes,second=0)
                            except:
                                days = days - 1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours,
                                                                                minute=minutes, second=0)

                    elif spectime == "hours":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
                                                                            hour=0,minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            hours = int(sectim / 3600)
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day=1 + days, hour=hours,minute=0,second=0)
                            except:
                                days = days -1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=hours, minute=0,
                                                                                second=0)

                    elif spectime == "days":
                        if j == 0:
                            starttime = log[i][j]['time:timestamp']
                            log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1, day=1,
                                                                            hour=0,minute=0,second=0)
                        else:
                            timedif = log[i][j]['time:timestamp'] - starttime
                            years = int(timedif.days / 365)
                            daystime = timedif.days - years * 365
                            month, days = self.month_translate(daystime)
                            sectim = timedif.seconds
                            # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                            # days = int(sectim / 3600 * 24)
                            try:
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970, month=1 + month,
                                                                            day= 1+ days, hour=0,minute=0,second=0)
                            except:
                                days = days -1
                                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR + 1970,
                                                                                month=1 + month,
                                                                                day=1 + days, hour=0, minute=0,
                                                                                second=0)

                    j += 1
                else:
                    del_list.append(log[i][j])
                    # log[i]._list.remove(log[i][j])
                    d += 1
                    j += 1
            for x in del_list:
                log[i]._list.remove(x)
                # d += 1
                # x += 1
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