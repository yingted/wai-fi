import sys
import sqlalchemy.orm

release = '--release' in sys.argv[1:]
sdk_dir = 'fw/esp_iot_sdk_v1.1.1'
data_dir = 'data/pki'

def _get_sql_uri():
	import os.path
	import re
	with open(os.path.expanduser('~/.pgpass')) as f:
		for line in f:
			host, port, database, user, password = line.rstrip('\n').split(':', 5)
			if database == 'wai-fi':
				return 'postgresql://%(user)s:%(password)s@%(host)s:%(port)s/%(database)s' % locals()
sql_engine = sqlalchemy.create_engine(_get_sql_uri())
sql_Session = sqlalchemy.orm.sessionmaker(bind=sql_engine)
