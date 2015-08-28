%module waifi_rpc
%{
#include <waifi_rpc.h>
%}
%include <waifi_rpc.h>

%include carrays.i
%array_functions(BYTE, bytep)
%array_functions(struct waifi_msg_log_logentry, logentryp)

%include cmalloc.i
%define CAST_HELPER(foo)
%inline %{
union foo ## _buf {
    struct foo value;
    BYTE buf[sizeof(struct foo)];
};
%}
%sizeof(struct foo, foo)
%pythoncode %{
def _scan_ ## foo(io):
    un = foo ## _buf()
    buf = io.read(sizeof_ ## foo)
    assert len(buf) <= sizeof_ ## foo
    if len(buf) != sizeof_ ## foo:
        raise EOFError('Read %d instead of %d bytes' % (len(buf), sizeof_ ## foo))
    _strncpy(un.buf, buf, sizeof_ ## foo)
    ret = un.value
    _refs[ret] = un # reference un until ret is deleted
    return ret
%}
%enddef
CAST_HELPER(waifi_msg_header)
CAST_HELPER(waifi_msg_log)
CAST_HELPER(waifi_rpc)
CAST_HELPER(waifi_msg_log_logentry)

%pythoncode %{
import struct
import abc
import weakref

def _strncpy(dst_buf, src_str, n):
    'Populate dst_buf (size n) with src_str.'
    for i in xrange(n):
        ch = 0
        if 0 <= i < len(src_str):
            ch, = struct.unpack('B', src_str[i])
        bytep_setitem(dst_buf, i, ch)

def _strndup(src_buf, n):
    r'''
    Copy a src_buf[:n] to a string.
    >>> b = new_bytep(4)
    >>> _strncpy(b, 'testing', 4)
    >>> _strndup(b, 4)
    'test'
    >>> _strncpy(b, 'x', 4)
    >>> _strndup(b, 2)
    'x\x00'
    '''
    return struct.pack('B' * n, *[bytep_getitem(src_buf, i) for i in xrange(n)])

_refs = weakref.WeakKeyDictionary()

class WaifiMsg(object):
    __metaclass__ = abc.ABCMeta
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            setattr(self, k, v)
    @classmethod
    def _filter_classes(cls, key, classes=None):
        if classes is None:
            classes = cls.__subclasses__()
        for x in classes:
            if x._key == key:
                return x
        raise TypeError('No class matching key %r in %r' % (key, classes))
    @classmethod
    def from_frame(cls, frame):
        hdr = _scan_waifi_msg_header(frame)
        return cls._filter_classes(hdr.type).from_frame(frame)

class WaifiLogMsg(WaifiMsg):
    _key = WAIFI_MSG_log
    @classmethod
    def from_frame(cls, frame):
        r'''
        >>> sizeof_waifi_msg_log_logentry
        25L
        >>> frame = struct.pack('BBh24sb', WAIFI_MSG_log, 0, 25, 'x' * 24, 100) + 'hello'
        >>> frame
        '\x00\x00\x19\x00xxxxxxxxxxxxxxxxxxxxxxxxdhello'
        >>> import cStringIO as StringIO
        >>> io = StringIO.StringIO(frame)
        >>> obj = WaifiMsg.from_frame(io)
        >>> io.tell() # should equal len(struct.pack(...)), which is 4 + 24 + 1
        29
        >>> obj # doctest: +ELLIPSIS
        <....WaifiLogMsg object at ...>
        >>> obj.entries # doctest: +ELLIPSIS
        [<...Swig Object of type 'waifi_msg_log_logentry *' at...>]
        >>> obj.entries[0].rssi
        100L
        '''
        log = _scan_waifi_msg_log(frame)
        # Must have an integral number of log entries.
        n, rem = divmod(log.len, sizeof_waifi_msg_log_logentry)
        if rem != 0:
            raise TypeError('Invalid message length')

        entries = []
        for _ in xrange(n):
            entry = _scan_waifi_msg_log_logentry(frame)
            fields = entry.header_fields
            import sys
            print >> sys.stderr, fields, dir(fields)
            entries.append(entry)

        assert len(entries) == n

        return cls(
            entries=entries,
        )
# vi:syntax=python
%}
