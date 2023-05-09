#activate_this = 'C:/Users/myuser/Envs/my_application/Scripts/activate_this.py'
# execfile(activate_this, dict(__file__=activate_this))
#exec(open(activate_this).read(),dict(__file__=activate_this))

import os
import sys
import site

# Add the site-packages of the chosen virtualenv to work with
#site.addsitedir('C:/Users/myuser/Envs/my_application/Lib/site-packages')




# Add the app's directory to the PYTHONPATH
sys.path.append('C:\MonitoringToolProject\MonitoringTool')
sys.path.append('C:\MonitoringToolProject\MonitoringTool\MonitoringTool')

os.environ['DJANGO_SETTINGS_MODULE'] = 'MonitoringTool.settings'
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "MonitoringTool.settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()