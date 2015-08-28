%module waifi_rpc
%{
#include <waifi_rpc.h>
%}
%include <waifi_rpc.h>

%include carrays.i
%array_functions(BYTE, bytep)
%array_functions(struct waifi_msg_log_logentry, logentryp)

%pythoncode %{
import multimethods
%}

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
def read_ ## foo(io):
    un = foo ## _buf()
    buf = io.read(sizeof_ ## foo)
    assert len(buf) <= sizeof_ ## foo
    if len(buf) != sizeof_ ## foo:
        raise EOFError('Read %d instead of %d bytes' % (len(buf), sizeof_ ## foo))
    strncpy(un.buf, buf, sizeof_ ## foo)
    ret = un.value
    _refs[ret] = un # reference un until ret is deleted
    return ret

@multimethods.multimethod(object, foo)
def write(io, obj):
    obj_buf = foo ## _buf()
    obj_buf.value = obj
    io.write(strndup(obj_buf.buf, sizeof_ ## foo))
%}
%enddef
CAST_HELPER(waifi_msg_header)
CAST_HELPER(waifi_msg_log)
CAST_HELPER(waifi_rpc)
CAST_HELPER(waifi_rpc_header)
CAST_HELPER(waifi_msg_log_logentry)

%pythoncode %{
import struct
import weakref

def strncpy(dst_buf, src_str, n):
    'Populate dst_buf (size n) with src_str.'
    for i in xrange(n):
        ch = 0
        if 0 <= i < len(src_str):
            ch, = struct.unpack('B', src_str[i])
        bytep_setitem(dst_buf, i, ch)

def strndup(src_buf, n):
    r'''
    Copy a src_buf[:n] to a string.
    >>> b = new_bytep(4)
    >>> strncpy(b, 'testing', 4)
    >>> strndup(b, 4)
    'test'
    >>> strncpy(b, 'x', 4)
    >>> strndup(b, 2)
    'x\x00'
    '''
    return struct.pack('B' * n, *[bytep_getitem(src_buf, i) for i in xrange(n)])

_refs = weakref.WeakKeyDictionary()

def _write_test():
    '''
    >>> import cStringIO as StringIO
    >>> inp = StringIO.StringIO('x' * sizeof_waifi_msg_log)
    >>> inp.getvalue()
    'xx'
    >>> x = read_waifi_msg_log(inp)
    >>> x # doctest: +ELLIPSIS
    <...Swig Object of type 'waifi_msg_log *' at ...>
    >>> out = StringIO.StringIO()
    >>> write(out, x)
    >>> out.getvalue()
    'xx'
    '''
# vi:syntax=python
%}
