from baseline import Baseline2
from pm4py.objects.log.importer.xes import factory as xes_import_factory

from pm4py.objects.log.exporter.xes import factory as xes_exporter
from pm4py.statistics.traces.log import case_statistics
from pm4py.algo.filtering.log.variants import variants_filter


event_log = "Sepsis Cases - Event Log.xes"
K = [10]
sensitive = ['Age', 'Diagnose']
spectime2 = ["hours", "minutes"]
for k in K:
    for t in spectime2:
        log = xes_import_factory.apply(event_log)
        base2 = Baseline2.Baseline2(log,sensitive,k,t)
        log2, d, d_l = base2.suppress_k_annonymity()
        var_with_count = case_statistics.get_variant_statistics(log2)
        variants_count = sorted(var_with_count, key=lambda x: x['count'], reverse=True)
        print(variants_count)
        print("deleted elements: " + str(d))
        print("deleted traces: " + str(d_l))
        xes_exporter.export_log(log2, "xes/baseline2" + "_" + t + str(k) + "-" + "Annonymity" + ".xes")
        print("xes/baseline2" + "_" + str(k) + "-" + "Annonymity" + ".xes" + " has been exported!")
