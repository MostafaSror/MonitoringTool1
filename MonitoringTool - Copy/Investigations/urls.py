from django.urls import path
from . import views


urlpatterns = [
    path('', views.index),
    path('getlogfilesinfoPage', views.grepForLogFilesInfoPage),
    path('searchmessagesinfopage', views.getMessagesInfoPage),
    path('searchforlogfilefn', views.search_log_file_fn),
    path('getmessagesfromlogsfn', views.get_messages_from_logs_fn),
    path('addserver', views.ServerCreateForm),
    path('addgroup', views.groupCreateForm),
    path('changelog', views.changeLogLevel),
    path('changelogfn', views.changeLogLevelFn),
    path('countexceptions', views.count_exceptions_page),
    path('countexceptionsfn', views.count_exception_fn),
    path('sendsoapinfo', views.check_soap_status_page),
    path('sendsoapinfofn', views.check_soap_status_fn),
    path('sendservicesoapinfopage', views.check_service_using_soap),
    path('sendservicesoapinfofn', views.check_service_soap_status_fn),
    path('sendhealthcheck', views.check_env_health_page),
    path('checkenvhealthfn', views.check_env_health_fn),
    path('archivedlogsinfo', views.check_archives_page),
    path('searcharchivefn', views.search_archive_fn),
    path('checkobipage', views.obieHandlingPage),
    path('checkobie', views.obie_handling_fn),
    path('checkschedulerpage', views.SchHandlingPage),
    path('startscheduler', views.start_sch_fn),
    path('runquery', views.db_queries_checker),
    path('deploypage', views.check_deploy_page),
    path('deployfn', views.deploy_fn),
    path('dashboardspage', views.check_dashboard_page),
    path('dashboardsfn', views.dashboards_fn),
    path('test', views.test),
    path('downloadmonitor', views.downloadMonitorPage),
    path('downloadmonitorfn', views.download_monitor_fn),
    path('gethealthgraphs', views.check_env_health_graphs_page),
    path('checkenvhealthgraphsfn', views.check_env_health_graphs_fn),
    path('getqueueshealthgraphs', views.check_queues_health_graphs_page),
    path('checkequeueshealthgraphsfn', views.check_queues_health_graphs_fn),
    path('getqueriesgraphs', views.check_queries_health_graphs_page),
    path('checkquerieshealthgraphsfn', views.check_queries_health_graphs_fn),
    path('getrepqueryresults', views.check_rep_query_monitor_page),
    path('checkrepqueriesfn', views.check_rep_queries_fn),
    path('getcommandexecuterPage', views.executeCommandPage),
    path('sendcommandfn', views.execute_command_fn),
    path('userinfopage', views.userinfopage),
    path('getcustfn', views.GetCustFn),
]
