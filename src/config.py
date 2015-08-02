import sqlalchemy

sdk_dir = 'fw/esp_iot_sdk_v1.1.1'
data_dir = 'data/pki'

sql_engine = sqlalchemy.create_engine('sqlite:///data/data.db')
