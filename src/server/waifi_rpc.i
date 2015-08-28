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
def _cast_ ## foo(buf):
    un = foo ## _buf()
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
    __slots__ = (
        'size',
    )
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            setattr(self, k, v)
    @classmethod
    def _from_frame(cls, frame):
        raise TypeError('No class found')
    @classmethod
    def from_frame(cls, frame):
        for subclass in cls.__subclasses__():
            instance = subclass.from_frame(frame)
            if instance != NotImplemented:
                return instance
        return cls._from_frame(memoryview(frame))

class WaifiLogMsg(WaifiMsg):
    __slots__ = (
        'entries',
    )
    @classmethod
    def _from_frame(cls, frame):
        r'''
        >>> sizeof_waifi_msg_log_logentry
        25L
        >>> frame = struct.pack('BBh24sb', WAIFI_MSG_log, 0, 25, 'x' * 24, 100)
        >>> frame
        '\x00\x00\x19\x00xxxxxxxxxxxxxxxxxxxxxxxxd'
        >>> obj = WaifiMsg.from_frame(frame)
        >>> obj # doctest: +ELLIPSIS
        <....WaifiLogMsg object at ...>
        >>> obj.size # should equal len(frame), which is 4 + 24 + 1
        29
        >>> obj.entries # doctest: +ELLIPSIS
        [<...Swig Object of type 'waifi_msg_log_logentry *' at...>]
        >>> obj.entries[0].rssi
        100L
        '''
        orig_len_frame = len(frame)
        obj = _cast_waifi_msg_header(frame)
        frame = frame[sizeof_waifi_msg_header:]
        if obj.type != WAIFI_MSG_log:
            return NotImplemented

        log = _cast_waifi_msg_log(frame)
        frame = frame[sizeof_waifi_msg_log:]
        n, rem = divmod(log.len, sizeof_waifi_msg_log_logentry)
        if rem != 0:
            raise TypeError('Invalid message length')
        if len(frame) < log.len:
            raise TypeError('Log entry buffer too short')

        entries = []
        for _ in xrange(n):
            assert len(frame) >= sizeof_waifi_msg_log_logentry
            entry_buf = frame[:sizeof_waifi_msg_log_logentry]
            frame = frame[sizeof_waifi_msg_log_logentry:]

            entry = _cast_waifi_msg_log_logentry(entry_buf)
            fields = entry.header_fields
            #import sys
            #print >> sys.stderr, fields, dir(fields)
            entries.append(entry)

        return cls(
            size=orig_len_frame - len(frame),
            entries=entries,
        )
# vi:syntax=python
%}
