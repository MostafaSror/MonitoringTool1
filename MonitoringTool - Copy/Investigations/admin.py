from django.contrib import admin
from .models import Server, Group, MiddlewareTechLookup, AppComponentTypesLookup, Error, Exceptions, Environment, \
    OnlineExceptionCount, FunctionalTool, SeverityLookup, Database, Query, AdaptorsAndApps, Resource, Configuration, \
    SoapRequest, SoapResponseStatus, Dashboard, ExceptionStatus, ExceptionsCounters, LK_Status, GroupLoggingLevel,\
    ExceptionsMonitor, QueriesMonitor, SoapRequestHeaders, RequestsMonitor, QueryNature, RepresentationalQuery, Service


class ServerAdmin(admin.ModelAdmin):
    list_display = ('IP', 'port', 'soap_port', 'hostname', 'name', 'group_name', 'log_path', 'archive_path', 'archive_mode', 'bin_path',
                    'resources_path', 'middleware_tech', 'os', 'app', 'logfile_prefix', 'app_user', 'app_password', 'soap_pass')


class GroupAdmin(admin.ModelAdmin):
    list_display = ('groupName', 'AppComponentTypeCode', 'get_environments', 'archiveCountPerDay', 'Status', 'LogsOpened', 'allow_monitoring')


class MiddlewareTechLookupAdmin(admin.ModelAdmin):
    list_display = ('TechName',)


class AppComponentTypesLookupAdmin(admin.ModelAdmin):
    list_display = ('ComponentTypeCode',)


class ErrorAdmin(admin.ModelAdmin):
    list_display = ('ErrorString', 'AppComponentType',)


class ExceptionAdmin(admin.ModelAdmin):
    list_display = ('id', 'Code', 'AppComponentType', 'Threshold', 'WarningThreshold', 'Group', 'ExceptionSeverity',
                    'Exception_Status', 'Description', 'count_btn_alerts', 'counter', 'interval_btn_alerts', 'lastAlertTime')


class EnvironmentAdmin(admin.ModelAdmin):
    list_display = ('envName',)


class OnlineExceptionCountAdmin(admin.ModelAdmin):
    list_display = ('round', 'exception_id', 'count')


class FunctionalToolAdmin(admin.ModelAdmin):
    list_display = ('Code', 'NamePrimary', 'get_tech')


class SeverityLookupAdmin(admin.ModelAdmin):
    list_display = ('Code',)


class ServiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')


class ExceptionStatusAdmin(admin.ModelAdmin):
    list_display = ('Code',)


class LKStatusAdmin(admin.ModelAdmin):
    list_display = ('Code',)


class ServiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'name',)


class DatabaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'IP', 'port', 'sid', 'service_name', 'user', 'password', 'db_type', 'getEnvs', 'allow_monitoring', 'getGroup')


class QueryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'query', 'getDatabases', 'Threshold', 'WarningThreshold', 'ExceptionSeverity', 'description', 'recepients_warning', 'recepients_alert', 'nature', 'timer')


class AdaptorsAndAppsAdmin(admin.ModelAdmin):
    list_display = ('Code', 'endpoint', 'getAppGroup')


class ResourceAdmin(admin.ModelAdmin):
    list_display = ('Code', 'serverIP', 'group', 'appType', 'srvFolderNames')


class ConfigurationAdmin(admin.ModelAdmin):
    list_display = ('id', 'key', 'value', 'env', 'description')


class SoapRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'body', 'uri', 'content_type', 'success_status', 'getGroup', 'getEnv', 'req_service', 'req_app', 'is_used_in_job')


class SoapRequestHeadersAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'key', 'value')


class SoapResponseStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'status', 'app', 'description')


class GroupLoggingLevelAdmin(admin.ModelAdmin):
    list_display = ('group', 'logs_opened_packages', 'logs_closed_packages', 'description')


class DashboardAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'physicalPath', 'hasAppRole', 'database')


class ExceptionsCountersAdmin(admin.ModelAdmin):
    list_display = ('Exception_id', 'server_id', 'count_btn_alerts', 'counter', 'interval_btn_alerts', 'lastAlertTime')


class ExceptionsMonitorAdmin(admin.ModelAdmin):
    list_display = ('Exception_id', 'group_id', 'server_id', 'count', 'lastAlertTime')


class QueriesMonitorAdmin(admin.ModelAdmin):
    list_display = ('Query_id', 'database_id', 'count', 'CaptureTime', 'severity')


class RequestsMonitorAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'group_id', 'server_id', 'counter')


class QueryNatureAdmin(admin.ModelAdmin):
    list_display = ('id', 'code')


class RepresentationalQueryAdmin(admin.ModelAdmin):
    list_display = ('id', 'QueryName', 'Query', 'headers', 'description', 'getEnvs', 'database', 'counter', 'nature', 'timer', 'positioning', 'is_missing_required')


admin.site.register(Server, ServerAdmin)
admin.site.register(Group, GroupAdmin)
admin.site.register(MiddlewareTechLookup, MiddlewareTechLookupAdmin)
admin.site.register(AppComponentTypesLookup, AppComponentTypesLookupAdmin)
admin.site.register(Error, ErrorAdmin)
admin.site.register(Exceptions, ExceptionAdmin)
admin.site.register(Environment, EnvironmentAdmin)
admin.site.register(OnlineExceptionCount, OnlineExceptionCountAdmin)
admin.site.register(FunctionalTool, FunctionalToolAdmin)
admin.site.register(SeverityLookup, SeverityLookupAdmin)
admin.site.register(Database, DatabaseAdmin)
admin.site.register(Query, QueryAdmin)
admin.site.register(AdaptorsAndApps, AdaptorsAndAppsAdmin)
admin.site.register(Resource, ResourceAdmin)
admin.site.register(Configuration, ConfigurationAdmin)
admin.site.register(SoapRequest, SoapRequestAdmin)
admin.site.register(GroupLoggingLevel, GroupLoggingLevelAdmin)
admin.site.register(Dashboard, DashboardAdmin)
admin.site.register(LK_Status, LKStatusAdmin)
admin.site.register(ExceptionStatus, ExceptionStatusAdmin)
admin.site.register(ExceptionsCounters, ExceptionsCountersAdmin)
admin.site.register(ExceptionsMonitor, ExceptionsMonitorAdmin)
admin.site.register(QueriesMonitor, QueriesMonitorAdmin)
admin.site.register(SoapRequestHeaders, SoapRequestHeadersAdmin)
admin.site.register(RequestsMonitor, RequestsMonitorAdmin)
admin.site.register(QueryNature, QueryNatureAdmin)
admin.site.register(RepresentationalQuery, RepresentationalQueryAdmin)
admin.site.register(Service, ServiceAdmin)
