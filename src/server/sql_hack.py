def escape_name(name):
	return '"%s"' % name.replace('"', '""')

def bulk_insert(session, objects):
	'session.bulk_insert(objects)'
	if len(objects) == 0:
		return
	first = objects[0]

	table = first.__table__
	escaped_tablename = escape_name(table.name)
	columns = list(table.columns)
	column_names = list(set(column.name for column in columns) & set(first.__dict__.keys()))
	format_string = '(%s)' % ','.join(['%s'] * len(column_names))
	cur = session.connection().connection.cursor()
	session.execute(
		'INSERT INTO %s(%s) VALUES %s' % (
			escape_name(table.name),
			','.join(
				map(escape_name, column_names)
			),
			','.join(
				cur.mogrify(format_string, [
					getattr(obj, column_name, None) for column_name in column_names
				]) for obj in objects
			),
		)
	)
	cur.close()
