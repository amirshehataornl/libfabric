from .fabric import *

SERVICE_NAME = 'libfabric'
SERVICE_DESC = 'libfabric communication library'

# This is used by the infrastructure to display information about
# the service module. The name is also used as a key through out the
# infrastructure. Without it the service module will not load.
svc_info = {'name': SERVICE_NAME,
			'module': __name__,
			'description': SERVICE_DESC,
			'version': 1.0}

# This is used by the infrastructure to define all the service classes.
# Each class should be a separate service. Each class should implement the
# following methods:
#	query()
#	reserve()
#	release()
service_classes = [Fabric]

def get_service_class():
	return service_classes[0]
