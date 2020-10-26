from typing import Tuple
import math
import random
import datetime
from pm4py.objects.log.log import EventLog
from pm4py.objects.log.log import Event
from pm4py.objects.log.importer.xes import factory as xes_import_factory
from pm4py.statistics.traces.log import case_statistics
from pm4py.objects.log.exporter.xes import factory as xes_exporter
import math
from pm4py.objects.log import log

class TrieNode(object):
    """
    Our trie node implementation. Very basic. but does the job
    """

    def __init__(self, pair: tuple,parent=None,root_bool = False):
        self.root = root_bool
        self.pair = pair
        self.dict_log = {}
        self.children = []
        self.parent = parent
        # Is it the last character of the word.`
        self.trace_finished = False
        # How many times this character appeared in the addition process
        self.counter = 1

    def __repr__(self, level=0):
        ret = "\t" * level + repr(self.pair) + " count: "+ repr(self.counter) + " caseIDs: " + repr(list(self.dict_log.keys())) + "\n"
        for child in self.children:
            ret += child.__repr__(level + 1)
        return ret

def add(root, dict_log: dict):
    """
    Adding a word in the trie structure
    """
    node = root
    key = list(dict_log.keys())[0]
    for pair in dict_log[key]['trace']:
        found_in_child = False
        # Search for the character in the children of the present `node`
        for child in node.children:
            if child.pair == pair:
                # We found it, increase the counter by 1 to keep track that another
                # trace has it as well
                child.counter += 1
                child.dict_log[key] = dict_log[key].copy()
                # And point the node to the child that contains this char
                node = child
                found_in_child = True
                break
        # We did not find it so add a new chlid
        if not found_in_child:
            new_node = TrieNode(pair, node)
            new_node.dict_log = dict_log.copy()
            node.children.append(new_node)
            # And then point node to the new child
            node = new_node
    # Everything finished. Mark it as the end of a word.
    node.trace_finished = True


def find_prefix(root, prefix: list) -> Tuple[bool, int]:
    """
    Check and return
      1. If the prefix exsists in any of the words we added so far
      2. If yes then how may words actually have the prefix
    """
    node = root
    # If the root node has no children, then return False.
    # Because it means we are trying to search in an empty trie
    if not root.children:
        return False, 0
    for pair in prefix:
        pair_not_found = True
        # Search through all the children of the present `node`
        for child in node.children:
            if child.pair == pair:
                # We found the char existing in the child.
                pair_not_found = False
                # Assign node as the child containing the char and break
                node = child
                break
        # Return False anyway when we did not find a char.
        if pair_not_found:
            return False, 0
    # Well, we are here means we have found the prefix. Return true to indicate that
    # And also the counter of the last node. This indicates how many words have this
    # prefix
    return True, node.counter

def get_leaf_nodes(root):
    leafs = {}
    def _get_leaf_nodes(node):
        if node is not None:
            if len(node.children) == 0:
                leafs.update(node.dict_log)
            for n in node.children:
                _get_leaf_nodes(n)
    _get_leaf_nodes(root)
    return leafs

def dfs(root,k):
    visited, stack = set(), [root]
    has_changes = False
    while stack:
        node = stack.pop()
        if node not in visited:
            if node.counter >= k:
                visited.add(node)
                stack.extend(node.children)
            elif not node.root:
                updateAncestors(root, node)
                prune(root, node)
                t_prime = {}
                for key in node.dict_log.keys():
                    t_prime[key] = {'trace': findMostSimilar(root,node,node.dict_log[key])}
                reconstructTree(root,t_prime)
                has_changes = True
            else:
                stack.extend(node.children)
    return has_changes

def check(root,k):
    has_changes = True
    while has_changes:
        has_changes = dfs(root,k)
    return root


def updateAncestors(root,node):
    count = node.counter
    parent = node.parent
    while not parent.root:
        parent.counter -= count
        parent = parent.parent

def prune(root,node):
    parent = node.parent
    parent.children.remove(node)
    while not parent.root:
        delete_keys = list(node.dict_log.keys())
        for key in delete_keys:
            parent.dict_log.pop(key, None)
        parent = parent.parent

def findMostSimilar(root,node,dict_key):
    parent = node.parent
    traces_parent = get_traces(root,parent.dict_log)
    dist = math.inf
    trace = dict_key['trace']
    candidate = []
    for trace_candidate in traces_parent:
        dist_cand = distance(root,trace,trace_candidate)
        if dist_cand < dist:
            dist = dist_cand
            candidate = trace_candidate
    return candidate

def get_traces(root,dict_cand):
    traces = []
    for key in dict_cand.keys():
        traces.append(dict_cand[key]['trace'])
    return traces

#trace1 is problem trace2 is candidate
def distance(root, trace1, trace2):
    mismatch = 0
    i = 0
    while i < len(trace1) and i < len(trace2):
        if trace1[i] != trace2[i]:
            mismatch += 1
            i += 1
            break
        else:
            i += 1
    for i2 in range(i,len(trace1)):
        mismatch += 1
    return mismatch


def reconstructTree(root,t_prime):
    for key in list(t_prime.keys()):
        add(root, {key: t_prime[key]})


def create_Tree(simple_log):
    root = TrieNode([],root_bool=True)
    for key in simple_log.keys():
        add(root, {key: simple_log[key]})
    return root


def simplify_without_time_count(log,sensitive):
    concept = ["concept:name"]
    logsimple = {}
    traces = []
    sensitives = {el: [] for el in sensitive}
    for case_index, case in enumerate(log):
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
                elif key in sensitive:
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

def suppress_k_annonymity(log,k,sensitive,t):
    logsimple,traces,sensitives = simplify_without_time_count(log,sensitive)
    root = create_Tree(logsimple)
    check(root,k)
    checked_log = get_leaf_nodes(root)
    log, d, d_l = createEventLog(log,checked_log,t)
    return log, d, d_l

def createEventLog(log,simplifiedlog,t):
    deleteLog = []
    log = log
    d = 0
    d_l = 0
    spectime = t
    for i in range(0, len(log)):
        caseId = log[i].attributes["concept:name"]
        if caseId not in simplifiedlog.keys():
            deleteLog.append(i)
            continue
        trace = simplifiedlog[caseId]["trace"]
        j = 0
        while j < len(log[i]) and j < len(trace):
            if trace[j][0] == log[i][j]["concept:name"]:
                if spectime == "seconds":
                    if j == 0:
                        starttime = log[i][j]['time:timestamp']
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                        hour=0, minute=0, second=0)
                    else:
                        timedif = log[i][j]['time:timestamp'] - starttime
                        years = int(timedif.days / 365)
                        daystime = timedif.days - years * 365
                        month, days = month_translate(daystime)
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
                        month, days = month_translate(daystime)
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
                        month, days = month_translate(daystime)
                        sectim = timedif.seconds
                        # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                        hours = int(sectim / 3600)
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                        day=1 + days, hour=hours,minute=0,second=0)
                j += 1
            else:
                if spectime == "seconds":
                    if j == 0:
                        starttime = log[i][j]['time:timestamp']
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                        hour=0, minute=0, second=0)
                        log[i][j]["concept:name"] = trace[j][0]
                    else:
                        timedif = log[i][j]['time:timestamp'] - starttime
                        years = int(timedif.days / 365)
                        daystime = timedif.days - years * 365
                        month, days = month_translate(daystime)
                        sectim = timedif.seconds
                        # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                        hours = int(sectim / 3600)
                        sectim = sectim - hours * 3600
                        minutes = int(sectim / 60)
                        sectim = sectim - minutes * 60
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                        day=1 + days, hour=hours,
                                                                        minute=minutes, second=sectim)
                        log[i][j]["concept:name"] = trace[j][0]
                elif spectime == "minutes":
                    if j == 0:
                        starttime = log[i][j]['time:timestamp']
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                        hour=0, minute=0, second=0)
                        log[i][j]["concept:name"] = trace[j][0]
                    else:
                        timedif = log[i][j]['time:timestamp'] - starttime
                        years = int(timedif.days / 365)
                        daystime = timedif.days - years * 365
                        month, days = month_translate(daystime)
                        sectim = timedif.seconds
                        # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                        hours = int(sectim / 3600)
                        sectim = sectim - hours * 3600
                        minutes = int(sectim / 60)
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                        day=1 + days, hour=hours,
                                                                        minute=minutes, second=0)
                        log[i][j]["concept:name"] = trace[j][0]
                elif spectime == "hours":
                    if j == 0:
                        starttime = log[i][j]['time:timestamp']
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1, day=1,
                                                                        hour=0, minute=0, second=0)
                        log[i][j]["concept:name"] = trace[j][0]
                    else:
                        timedif = log[i][j]['time:timestamp'] - starttime
                        years = int(timedif.days / 365)
                        daystime = timedif.days - years * 365
                        month, days = month_translate(daystime)
                        sectim = timedif.seconds
                        # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                        hours = int(sectim / 3600)
                        log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                        day=1 + days, hour=hours, minute=0, second=0)
                        log[i][j]["concept:name"] = trace[j][0]
                j += 1
        while j < len(trace):
            if spectime == "seconds":
                timedif = datetime.timedelta(seconds=random.randrange(0,1000))
                years = int(timedif.days / 365)
                daystime = timedif.days - years * 365
                month, days = month_translate(daystime)
                sectim = timedif.seconds
                # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                hours = int(sectim / 3600)
                sectim = sectim - hours * 3600
                minutes = int(sectim / 60)
                sectim = sectim - minutes * 60
                log[i].append(Event())
                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                day=1 + days, hour=hours,
                                                                minute=minutes, second=sectim)
                log[i][j]["concept:name"] = trace[j][0]
            elif spectime == "minutes":
                timedif = datetime.timedelta(seconds=random.randrange(0,1000))
                years = int(timedif.days / 365)
                daystime = timedif.days - years * 365
                month, days = month_translate(daystime)
                sectim = timedif.seconds
                # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                hours = int(sectim / 3600)
                sectim = sectim - hours * 3600
                minutes = int(sectim / 60)
                log[i].append(Event())
                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                day=1 + days, hour=hours,
                                                                minute=minutes, second=0)
                log[i][j]["concept:name"] = trace[j][0]
            elif spectime == "hours":
                timedif = datetime.timedelta(seconds=random.randrange(0,1000))
                years = int(timedif.days / 365)
                daystime = timedif.days - years * 365
                month, days = month_translate(daystime)
                sectim = timedif.seconds
                # 60sec -> 1 min, 60*60sec -> 60 min -> 1 hour
                hours = int(sectim / 3600)
                log[i].append(Event())
                log[i][j]['time:timestamp'] = datetime.datetime(year=datetime.MINYEAR, month=1 + month,
                                                                day=1 + days, hour=hours, minute=0, second=0)
                log[i][j]["concept:name"] = trace[j][0]
            j += 1
        if j < len(log[i]):
            for k in range(len(log[i]) - 1, j -1 ,-1):
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

def month_translate(daystime):
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

if __name__ == "__main__":
    #event_log2 = "LKC_Artificial2.xes"
    event_log = "Sepsis Cases - Event Log.xes"
    K = [10]
    sensitive = ['Age', 'Diagnose']
    spectime2 = ["hours", "minutes"]
    for k in K:
        for t in spectime2:
            log = xes_import_factory.apply(event_log)
            log2, d, d_l = suppress_k_annonymity(log,k, sensitive, t)
            var_with_count = case_statistics.get_variant_statistics(log2)
            variants_count = sorted(var_with_count, key=lambda x: x['count'], reverse=True)
            print(variants_count)
            print(len(variants_count))
            print("deleted elements: " + str(d))
            print("deleted traces: " + str(d_l))
            xes_exporter.export_log(log2, "xes/baseline3" + "_" + t + str(k) + "-" + "Annonymity" + ".xes")
            print("xes/baseline3" + "_" + str(k) + "-" + "Annonymity" + ".xes" + " has been exported!")