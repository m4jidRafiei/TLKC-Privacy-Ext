from pm4py.objects.log.importer.xes import factory as xes_import_factory
from pm4py.objects.log.exporter.xes import factory as xes_exporter
from pm4py.statistics.traces.log import case_statistics
from pm4py.algo.filtering.log.variants import variants_filter


K = [20]
for k in K:
    event_log = "Sepsis Cases - Event Log.xes"
    log = xes_import_factory.apply(event_log)
    var_with_count = case_statistics.get_variant_statistics(log)
    variants_count = sorted(var_with_count, key=lambda x: x['count'], reverse=True)
    to_filter = []
    count = 0
    for j in range(0, len(variants_count)):
        dict = variants_count[j]
        if dict["count"] < k:
            to_filter.append([dict["variant"]])
        else:
            count += dict["count"]
    for delete in to_filter:
        log = variants_filter.apply(log, delete,parameters={"positive": False})
    xes_exporter.export_log(log, "xes/baseline" + "_" + str(k) + "-" + "Annonymity" + ".xes")
    print("xes/baseline" + "_" + str(k) + "-" + "Annonymity" + ".xes" + " has been exported!")