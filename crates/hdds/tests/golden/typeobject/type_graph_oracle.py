# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Independent XCDR2-LE encoder from DDS-XTypes 1.3 Annex B and 7.4.3.
# No HDDS bytes or functions are read. Alignment is relative to stream start.
import struct, hashlib
class Cdr:
    def __init__(self): self.b=bytearray()
    def raw(self,b): self.b.extend(b)
    def n(self,n,size):
        self.raw(bytes((-len(self.b)) % size)); self.raw(n.to_bytes(size,'little'))
    def text(self,s): self.n(len(s)+1,4); self.raw(s.encode()+b'\0')
    def dh(self,f):
        self.n(0,4); p=len(self.b); f(); self.b[p-4:p]=struct.pack('<I',len(self.b)-p)
    def ident(self,i):
        if isinstance(i,int): self.n(i,1)
        elif i[0]=='hash': self.n(i[1],1); self.raw(i[2])
        elif i[0]=='seq':
            self.n(0x80,1); self.n(i[1],1); self.n(1,2); self.n(3,1); self.ident(i[2])
        elif i[0]=='array':
            self.n(0x90,1); self.n(i[1],1); self.n(1,2); self.n(1,4); self.n(2,1); self.ident(i[2])
    def detail(self,name): self.raw(b'\0\0'); self.text(name)
    def structure(self,name,member,complete):
        self.n(0x51,1); self.n(1,2)
        def header():
            self.n(0,1)
            if complete:self.detail(name)
        self.dh(header)
        def sequence():
            self.n(1,4)
            def m():
                self.n(0,4);self.n(1,2);self.ident(member)
                if complete: self.text('x');self.raw(b'\0\0')
                else:self.raw(hashlib.md5(b'x').digest()[:4])
            self.dh(m)
        self.dh(sequence)
    def alias(self,name,related,complete):
        self.n(0x30,1);self.n(0,2)
        self.dh(lambda:self.detail(name) if complete else None)
        def body():
            self.n(0,2);self.ident(related)
            if complete:self.raw(b'\0\0')
        self.dh(body)
def obj(complete,encode):
    c=Cdr(); c.dh(lambda:(c.n(0xf2 if complete else 0xf1,1),encode(c)))
    return hashlib.md5(c.b).digest()[:14]
for complete in [False,True]:
    k=0xf2 if complete else 0xf1
    leaf=obj(complete,lambda c:c.structure('Leaf',4,complete))
    alias=obj(complete,lambda c:c.alias('Alias',('hash',k,leaf),complete))
    root=obj(complete,lambda c:c.structure('Root',('seq',k,('array',k,('hash',k,leaf))),complete))
    print('Complete' if complete else 'Minimal', 'leaf',leaf.hex(),'alias',alias.hex(),'root',root.hex())
