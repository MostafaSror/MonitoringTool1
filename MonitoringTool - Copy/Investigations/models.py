from django.db import models
import datetime


class AppComponentTypesLookup(models.Model):
    id = models.AutoField(primary_key=True)
    ComponentTypeCode = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.ComponentTypeCode


class SeverityLookup(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.Code


class LK_Status(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.Code

    class Meta:
        verbose_name_plural = "LK_Status"


class Service(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Services"


class ExceptionStatus(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.Code

    class Meta:
        verbose_name_plural = "Statuses"


class Environment(models.Model):
    id = models.AutoField(primary_key=True)
    envName = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.envName


class Group(models.Model):
    id = models.AutoField(primary_key=True)
    groupName = models.CharField(max_length=64, unique=True)
    AppComponentTypeCode = models.ForeignKey(AppComponentTypesLookup, null=True, verbose_name="AppComponentType",
                                         on_delete=models.SET_NULL)
    environments = models.ManyToManyField(Environment)
    archiveCountPerDay = models.CharField(max_length=64, null=True)
    Status = models.ForeignKey(LK_Status, null=True, on_delete=models.SET_NULL)
    LogsOpened = models.CharField(max_length=64, null=True, default='true')
    allow_monitoring = models.BooleanField(default=True)

    def __str__(self):
        return self.groupName

    def get_environments(self):
        return "\n".join([p.envName for p in self.environments.all()])


class MiddlewareTechLookup(models.Model):
    id = models.AutoField(primary_key=True)
    TechName = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.TechName


class Error(models.Model):
    id = models.AutoField(primary_key=True)
    ErrorString = models.CharField(max_length=200)
    AppComponentType = models.ForeignKey(AppComponentTypesLookup, null=True, verbose_name="AppComponentType", on_delete= models.SET_NULL)

    def __str__(self):
        return self.ErrorString
    class Meta:
        unique_together = ('ErrorString', 'AppComponentType')


class Exceptions(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=False)
    AppComponentType = models.ForeignKey(AppComponentTypesLookup, null=True, blank=True,
                                         verbose_name="AppComponentType", on_delete= models.SET_NULL)
    Threshold = models.CharField(max_length=64, null=True, blank=True)
    WarningThreshold = models.CharField(max_length=64, null=True, blank=True)
    ExceptionSeverity = models.ForeignKey(SeverityLookup, null=True, blank=True,
                                          verbose_name="Severity", on_delete=models.SET_NULL)
    Exception_Status = models.ForeignKey(ExceptionStatus, null=True, on_delete=models.SET_NULL)
    Group = models.ForeignKey(Group, null=True, blank=True, verbose_name="Group", on_delete=models.CASCADE)
    Description = models.CharField(max_length=1000, unique=False, null=True, blank=True)
    count_btn_alerts = models.IntegerField(null=True, default=0)
    counter = models.IntegerField(null=True, default=0)
    interval_btn_alerts = models.IntegerField(null=True, default=10)
    lastAlertTime = models.DateTimeField(default=datetime.datetime.now())

    def __str__(self):
        return self.Code

    class Meta:
        unique_together = ('Code', 'AppComponentType', 'Group')
        verbose_name_plural = "Exceptions"


class OnlineExceptionCount(models.Model):
    id = models.AutoField(primary_key=True)
    round = models.IntegerField()
    exception_id = models.ForeignKey(Exceptions, default=1, verbose_name="id", on_delete=models.CASCADE)
    count = models.IntegerField()

    class Meta:
        verbose_name_plural = "OnlineExceptionCounts"


class FunctionalTool(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=True)
    NamePrimary = models.CharField(max_length=200, unique=False)
    env_validity = models.ManyToManyField(MiddlewareTechLookup)

    class Meta:
        verbose_name_plural = "FunctionalTools"

    def __str__(self):
        return self.NamePrimary

    def get_tech(self):
        return "\n".join([p.TechName for p in self.env_validity.all()])


class AdaptorsAndApps(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=True)
    endpoint = models.CharField(max_length=300, unique=False, blank=True)
    group_availability = models.ManyToManyField(Group)

    class Meta:
        verbose_name_plural = "AdaptorsAndApps"

    def __str__(self):
        return self.Code

    def getAppGroup(self):
        return "\n".join([p.groupName for p in self.group_availability.all()])


class Server(models.Model):
    id = models.AutoField(primary_key=True)
    IP = models.CharField(max_length=16, unique=True)
    port = models.CharField(max_length=5, null=True, blank=True)
    soap_port = models.CharField(max_length=5, null=True, blank=True)
    hostname = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=16, default='Active')
    group_name = models.ForeignKey(Group, default=1, verbose_name="group", on_delete=models.SET_DEFAULT)
    log_path = models.CharField(max_length=150, null=True, blank=True)
    bin_path = models.CharField(max_length=150, null=True, blank=True)
    resources_path = models.CharField(max_length=150, null=True, blank=True)
    archive_path = models.CharField(max_length=150, null=True, blank=True)
    archive_mode = models.CharField(max_length=150, null=True, blank=True, default='default')
    middleware_tech = models.ForeignKey(MiddlewareTechLookup, null=True, verbose_name="MW_Tech", on_delete=models.SET_NULL)
    os = models.CharField(max_length=32, default='aix')
    app = models.ForeignKey(AdaptorsAndApps, null=True, blank=True, verbose_name="app", on_delete=models.SET_NULL, default=None)
    logfile_prefix = models.CharField(max_length=30, null=True, blank=True, default=None)
    app_user = models.CharField(max_length=30, null=True, default=None)
    app_password = models.CharField(max_length=30, null=True, default=None)
    soap_pass = models.CharField(max_length=30, null=True, default=None, blank=True)

    class Meta:
        verbose_name_plural = "Servers"
        unique_together = ('IP', 'group_name')

    def __str__(self):
        return self.IP


class Resource(models.Model):
    id = models.AutoField(primary_key=True)
    Code = models.CharField(max_length=200, unique=False, blank=True)
    serverIP = models.ForeignKey(Server, default=1, blank=True, null=True, verbose_name="serverIP", on_delete=models.SET_DEFAULT)
    group = models.ForeignKey(Group, default=None, blank=True, null=True, verbose_name="Group", on_delete=models.SET_NULL)
    appType = models.ForeignKey(AdaptorsAndApps, default=1, verbose_name="appType", on_delete=models.SET_DEFAULT)
    srvFolderNames = models.CharField(max_length=200, unique=False, blank=True)

    class Meta:
        verbose_name_plural = "Resources"
        unique_together = ('serverIP', 'group', 'appType')

    def __str__(self):
        return self.Code


class Database(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=64, null=False)
    IP = models.CharField(max_length=16, unique=False)
    port = models.CharField(max_length=5, null=True)
    sid = models.CharField(max_length=30, null=True, blank=True)
    service_name = models.CharField(max_length=30, null=True, blank=True)
    user = models.CharField(max_length=50, null=False, default=None)
    password = models.CharField(max_length=50, null=False, default=None)
    db_type = models.CharField(max_length=64, null=False)
    environment = models.ManyToManyField(Environment)
    allow_monitoring = models.BooleanField(default=True)
    app_group = models.ManyToManyField(Group, verbose_name="group_name", null=True, blank=True, default=None)

    class Meta:
        verbose_name_plural = "Databases"
        unique_together = ('IP', 'port', 'user')

    def __str__(self):
        return self.name

    def getGroup(self):
        return "\n".join([p.groupName for p in self.app_group.all()])

    def getEnvs(self):
        return "\n".join([p.envName for p in self.environment.all()])


class QueryNature(models.Model):
    id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=20, unique=False)

    def __str__(self):
        return self.code


class Query(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=False, null=True)
    query = models.CharField(max_length=2000, unique=False)
    database_name = models.ManyToManyField(Database, verbose_name="db_name")
    Threshold = models.CharField(max_length=64, null=True, blank=True)
    WarningThreshold = models.CharField(max_length=64, null=True, blank=True)
    ExceptionSeverity = models.ForeignKey(SeverityLookup, null=True, blank=True,
                                          verbose_name="Severity", on_delete=models.SET_NULL)
    description = models.CharField(max_length=1000, unique=False, default='description')
    recepients_warning = models.CharField(max_length=1000, unique=False, default='')
    recepients_alert = models.CharField(max_length=1000, unique=False, default='')
    nature = models.ForeignKey(QueryNature, null=True, blank=True,
                               verbose_name="nature", on_delete=models.SET_NULL, default=1)
    timer = models.IntegerField(null=True, default=5)

    class Meta:
        verbose_name_plural = "Queries"

    def __str__(self):
        return '{} {} {} {} {}'.format(self.query, self.database_name, self.Threshold, self.WarningThreshold, self.ExceptionSeverity)

    def getDatabases(self):
        return "\n".join([p.name for p in self.database_name.all()])


class RepresentationalQuery(models.Model):
    id = models.AutoField(primary_key=True)
    QueryName = models.CharField(max_length=150)
    Query = models.CharField(max_length=10000, unique=False)
    headers = models.CharField(max_length=10000, unique=False, default='')
    description = models.CharField(max_length=1000, unique=False, default='description')
    environments = models.ManyToManyField(Environment)
    database = models.ForeignKey(Database, null=True, blank=True, on_delete=models.SET_NULL)
    counter = models.CharField(max_length=1000, unique=False, null=True)
    nature = models.ForeignKey(QueryNature, null=True, blank=True,
                               verbose_name="nature", on_delete=models.SET_NULL, default=1)
    timer = models.IntegerField(null=True, default=0)
    positioning = models.IntegerField(null=True, default=1)
    is_missing_required = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "RepresentationalQueries"

    def getEnvs(self):
        return "\n".join([p.envName for p in self.environments.all()])


class SoapRequest(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=32, null=True, blank=True)
    body = models.CharField(max_length=10000, null=True, blank=True)
    uri = models.CharField(max_length=128)
    type = models.CharField(max_length=32, default='post')
    content_type = models.CharField(max_length=64, null=True, blank=True, default='text/xml')
    success_status = models.CharField(max_length=64, null=True, blank=True, default='<StatusCode>200</StatusCode>')
    req_group = models.ManyToManyField(Group, verbose_name="group_name")
    req_env = models.ManyToManyField(Environment, verbose_name="env_name")
    req_service = models.ForeignKey(Service, null=True, blank=True, verbose_name="service_name", on_delete=models.SET_NULL)
    req_app = models.ForeignKey(AdaptorsAndApps, null=True, verbose_name="app_name", on_delete=models.SET_NULL)
    response_code = models.CharField(max_length=32, null=True, blank=True)
    is_used_in_job = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "SoapRequests"

    def __str__(self):
        return str(self.id)

    def getGroup(self):
        return "\n".join([p.groupName for p in self.req_group.all()])

    def getEnv(self):
        return "\n".join([p.envName for p in self.req_env.all()])


class SoapRequestHeaders(models.Model):
    key = models.CharField(max_length=32, blank=True)
    value = models.CharField(max_length=10000, blank=True)
    request_id = models.ForeignKey(SoapRequest, null=True, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = "SoapRequestHeaders"


class SoapResponseStatus(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=32, null=True, blank=True)
    status = models.CharField(max_length=64, null=True, blank=True, default='<StatusCode>200</StatusCode>')
    app = models.ForeignKey(AdaptorsAndApps, null=True, verbose_name="app_name", on_delete=models.SET_NULL)
    description = models.CharField(max_length=500, null=True, blank=True)

    class Meta:
        verbose_name_plural = "ResponseStatuses"


class GroupLoggingLevel(models.Model):
    id = models.AutoField(primary_key=True)
    group = models.ForeignKey(Group, null=True, verbose_name="group_name", on_delete=models.SET_NULL)
    logs_opened_packages = models.CharField(max_length=2000)
    logs_closed_packages = models.CharField(max_length=2000)
    description = models.CharField(max_length=500, null=True, blank=True)

    class Meta:
        verbose_name_plural = "GroupLoggingLevels"


class Configuration(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=1000)
    value = models.CharField(max_length=1000)
    env = models.CharField(max_length=32, blank=True, null=True)
    description = models.CharField(max_length=1000, blank=True, null=True)

    class Meta:
        verbose_name_plural = "Configuration"
        unique_together = ('key', 'env')


class Dashboard(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000)
    physicalPath = models.CharField(max_length=1000, unique=True)
    hasAppRole = models.BooleanField(default=False)
    database = models.ForeignKey(Database, null=True, blank=True, verbose_name="db_name", on_delete=models.SET_NULL)

    class Meta:
        verbose_name_plural = "Dashboards"


class ExceptionsCounters(models.Model):
    id = models.AutoField(primary_key=True)
    Exception_id = models.ForeignKey(Exceptions, verbose_name="Exception", on_delete=models.CASCADE)
    server_id = models.ForeignKey(Server, verbose_name="Server", on_delete=models.CASCADE)
    count_btn_alerts = models.IntegerField(null=True, default=0)
    counter = models.IntegerField(null=True, default=0)
    interval_btn_alerts = models.IntegerField(null=True, default=10)
    lastAlertTime = models.DateTimeField(default=datetime.datetime.now())

    class Meta:
        unique_together = ('Exception_id', 'server_id')
        verbose_name_plural = "ExceptionsCounters"


class ExceptionsMonitor(models.Model):
    id = models.AutoField(primary_key=True)
    Exception_id = models.ForeignKey(Exceptions, verbose_name="Exception", on_delete=models.CASCADE)
    group_id = models.ForeignKey(Group, verbose_name="group", on_delete=models.CASCADE, null=True)
    server_id = models.ForeignKey(Server, verbose_name="Server", on_delete=models.CASCADE)
    count = models.IntegerField(null=True, default=0)
    lastAlertTime = models.DateTimeField(default=datetime.datetime.now())

    class Meta:
        verbose_name_plural = "ExceptionsMonitor"


class QueriesMonitor(models.Model):
    id = models.AutoField(primary_key=True)
    Query_id = models.ForeignKey(Query, verbose_name="Queries", on_delete=models.CASCADE)
    database_id = models.ForeignKey(Database, verbose_name="Databases", on_delete=models.CASCADE)
    count = models.IntegerField(null=True, default=0)
    CaptureTime = models.DateTimeField(default=datetime.datetime.now())
    severity = models.CharField(max_length=50, null=True)

    class Meta:
        verbose_name_plural = "QueriesMonitor"


class RequestsMonitor(models.Model):
    id = models.AutoField(primary_key=True)
    request_id = models.ForeignKey(SoapRequest, verbose_name="Request", on_delete=models.CASCADE)
    group_id = models.ForeignKey(Group, verbose_name="group", on_delete=models.CASCADE, null=True)
    server_id = models.ForeignKey(Server, verbose_name="Server", on_delete=models.CASCADE)
    counter = models.IntegerField(null=True, default=0)

    class Meta:
        verbose_name_plural = "RequestsMonitor"