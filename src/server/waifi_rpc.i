%module waifi_rpc
%{
#include <waifi_rpc.h>
%}
%include <waifi_rpc.h>
%typemap(in) unsigned char[ANY] {
    if (!PyString_Check($input)) {
        PyErr_Format(PyExc_TypeError, "must be string, not '%.200s'", $input->ob_type->tp_name);
        return -1;
    }
    memset($1, 0, $dim0);
    memcpy($1, $input, min($dim0, PyString_Size($input)));
}
%typemap(out) unsigned char[ANY] {
    $result = SWIG_FromCharPtrAndSize($1, $dim0);
}

%pythoncode %{
def decode_waifi_msg(frame):
    obj = waifi_msg_buf()
    print len(obj.buf)
    obj.buf = frame
    print obj.value
decode_waifi_msg('000003616263'.decode('hex'))
# vi:syntax=python
%}
