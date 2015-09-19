#!/usr/bin/env python2
import sys, struct, subprocess, os.path, pipes

def _read_struct(f, spec):
    n = struct.calcsize(spec)
    s = f.read(n)
    if len(s) != n: # failed
        return s, struct.unpack(spec, '\0' * n)
    return None, struct.unpack(spec, s)

def dump(f):
    rest, (magic0, magic1, flash_mode, flash_map, entry_addr) = _read_struct(f, '<BBBBI')
    print hex(magic0), magic1, flash_mode, '0x%02x' % flash_map, 'entry=0x%08x' % entry_addr
    while True:
        rest, (addr, size) = _read_struct(f, '<II')
        if rest is not None:
            break
        start_pos = f.tell()
        data = f.read(size)
        if len(data) < size or size == 0:
            rest = data
            break
        end_pos = f.tell()
        assert start_pos + size == end_pos
        vma = addr - start_pos
        vma %= 2**32
        cmd = (
            'xtensa-lx106-elf-objdump', '-Drz', '-m', 'xtensa', '-b', 'binary',
            '--adjust-vma=0x%08x' % vma,
            '--start-address=0x%08x' % (vma + start_pos),
            '--stop-address=0x%08x' % (vma + end_pos),
            os.path.abspath(os.path.realpath('/proc/self/fd/%d' % f.fileno())),
        )
        print 'Run:', ' '.join(map(pipes.quote, cmd))
        sys.stdout.flush()
        subprocess.check_call(cmd)
    assert rest[:-1] == '\0' * len(rest[:-1])

if __name__ == '__main__':
    dump(sys.stdin)
