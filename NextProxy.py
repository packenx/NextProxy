# -*- coding: utf-8 -*-
# <NextProxy.py>

import select
import socket
import time

from multiprocessing import Process

__version__="0.7.2"

ssl_ua="Next Proxy/"+__version__
ssl_ver="HTTP/1.1"

recvlen=1024

sev_host="localhost"
sev_port=8080

class httpparse:

    def __init__(self,buf):
        self.header=None
        self.header_info=None
        self.CL,self.CO="\r\n",":"
        header_line=buf.strip().split(self.CL)
        self.header_info=header_line.pop(0).split(" ",2)
        self.header=dict()
        for line in header_line:
            k,_=line.split(self.CO,1)
            self.header[k.lower()]=line

    def read_header(self,reader,vstrip=True,kstrip=False):
        reader=reader.lower()
        if kstrip:
            reader=reader.strip()
            for v in self.header:
                if v.strip() == reader:
                    _,v=self.header[v].split(self.CO,1)
                    if vstrip:return v.strip()
                    else:return v
        else:
            if self.header.has_key(reader):
                _,v=self.header[reader].split(self.CO,1)
                if vstrip:return v.strip()
                else:return v
        return ""

    def del_header(self,del_header,unstrip=True):
        for k in del_header:
            k=k.lower()
            if unstrip:
                if self.header.has_key(k):del self.header[k]
            else:
                k=k.strip()
                for v in self.header:
                    if v.strip() == k:del self.header[v]

    def add_header(self,add_header):
        for v in add_header:
            k,_=v.split(self.CO,1)
            self.header[k.lower()]=v

    def get_info(self,info=3):
        if info < 3:
            return self.header_info[info]
        else:
            return " ".join(self.header_info)+self.CL

    def edit_info(self,info,v):
        self.header_info[info]=v

    def build_header(self):
        res=self.get_info()
        for k in self.header:
            res=res+self.header[k]+self.CL
        return res+self.CL

class httpproxy:

    def __init__(self,socin,address):
        self.sslvc=False
        try:
            socout=self.req(socin)
            if self.sslvc:
                self.loop_rw(socin,socout)
            else:
                self.res(socout,socin)
        except socket.error,e:
            print address,"~",e###
        except NotImplementedError,e:
            print address,"~",e###
        socin.close()
        try:
            socout.close()
        except UnboundLocalError,e:
            pass

    def req(self,socin):
        buf,point=self.load(socin)
        reqparse=httpparse(buf[:point])
        buf=buf[point:]
        print reqparse.get_info()###
        point=reqparse.get_info(0).lower()
        if point == "get":
            buf=None
            socout=self.do_get(reqparse)
        elif point == "post":
            socout=self.do_post(reqparse,buf,socin)
        elif point == "connect":
            buf=None
            socout=self.do_connect(reqparse,socin)
        else:
            raise NotImplementedError("close",reqparse.get_info(0))
        return socout

    def res(self,socin,socout):
        buf,point=self.load(socin)
        resparse=httpparse(buf[:point])
        buf=buf[point:]
        socout.sendall(resparse.build_header())
        if self.get_length(resparse):
            self.chunkdata(buf,socin,socout)
        else:
            self.lengthdata(resparse,buf,socin,socout)

    def do_get(self,reqparse):
        host=self.get_host(reqparse)
        socout=self.conn(host)
        socout.sendall(reqparse.build_header())
        return socout

    def do_post(self,reqparse,buf,socin):
        host=self.get_host(reqparse)
        socout=self.conn(host)
        socout.sendall(reqparse.build_header())
        if self.get_length(reqparse):
            self.chunkdata(buf,socin,socout)
        else:
            self.lengthdata(reqparse,buf,socin,socout)
        return socout

    def do_connect(self,reqparse,socobj):
        host=self.get_host(reqparse)
        soconn=self.conn(host)
        socobj.sendall("%s 200 Connection established\r\nProxy-agent: %s\r\n\r\n"%(ssl_ver,ssl_ua))
        self.sslvc=True
        return soconn

    def chunkdata(self,buf,socin,socout):
        while True:
            point=buf.find("\r\n")
            if point != -1:
                size=buf[:point]
                buf=buf[point:]
            else:
                buf,point=self.load(socin,"\r\n",buf)
                size=buf[:point-2]
                buf=buf[point-2:]
            if size.find(";") != -1:
                intsize=int(size[:size.find(";")],16)
            else:
                intsize=int(size,16)
            if not intsize:
                point=buf.find("\r\n\r\n")
                if point != -1:
                    buf=buf[:point+4]
                else:
                    buf,point=self.load(socin,"\r\n\r\n",buf)
                    buf=buf[:point]
                bodys=size+buf
                socout.sendall(bodys)
                break
            else:
                buf_len=len(buf)
                if buf_len >= intsize+4:
                    socout.sendall(size+buf[:intsize+4])
                    buf=buf[intsize+4:]
                else:
                    socout.sendall(buf)
                    buf=""
                    self.lorw_len(intsize+4-buf_len,socin,socout)

    def lengthdata(self,parsething,buf,socin,socout):
        get_len=parsething.read_header("content-length")
        if get_len:get_len=int(get_len)
        else:get_len=0
        if len(buf) < get_len:
            socout.sendall(buf)
            self.lorw_len(get_len-len(buf),socin,socout)
        else:
            socout.sendall(buf[:get_len])

    def load(self,socobj,keywords="\r\n\r\n",buf="",outs=7):
        len_header=None
        tout=time.time()+outs
        while time.time() < tout:
            tmps=socobj.recv(recvlen)
            if tmps:
                buf += tmps
                tout=time.time()+outs
                len_header=buf.find(keywords)
                if len_header != -1:break
            else:
                time.sleep(0.001)
            
        else:
            raise socket.error("load","timeout")
        return buf,len_header+len(keywords)

    def lorw_len(self,get_len,socin,socout,outs=7):
        notime=time.time()+outs
        while time.time() < notime:
            buf=socin.recv(get_len)
            if buf:
                get_len -= len(buf)
                socout.sendall(buf)
                notime=time.time()+outs
                if not get_len:break
            else:
                time.sleep(0.001)
        else:
            raise socket.error("recv","timeout")

    def get_host(self,parsething):
        path=parsething.get_info(1)
        if path.startswith("http://"):
            path=path[7:]
            i=path.find("/")
            host=path[:i]
            path=path[i:]
            parsething.edit_info(1,path)
        else:
            host=parsething.read_header("host")
        parsething.del_header(["proxy-connection","keep-alive"])
        parsething.add_header(["Connection: Close"])
        return host

    def get_length(self,parsething):
        thing=parsething.read_header("transfer-encoding").lower()
        if thing == "chunked":
            return True
        else:
            return False

    def conn(self,host):
        i=host.find(":")
        if i != -1:
            port=int(host[i+1:])
            host=host[:i]
        else:
            port=80
        (soc_family,_,_,_,address)=socket.getaddrinfo(host,port)[0]
        socobj=socket.socket(soc_family)
        socobj.connect(address)
        return socobj

    def loop_rw(self,socin,socout,timeout=7):
        socs=[socin,socout]
        count=0
        while count != timeout:
            count += 1
            (recv,_,error)=select.select(socs,[],socs,1)
            if error:
                break
            if recv:
                for in_ in recv:
                    data=in_.recv(recvlen)
                    if in_ is socin:
                        out=socout
                    else:
                        out=socin
                    if data:
                        out.sendall(data)
                        count=0

if __name__ == "__main__":
    soc=socket.socket(socket.AF_INET)
    soc.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    soc.bind((sev_host,sev_port))
    print "Serving on %s:%d."%(sev_host,sev_port)###
    soc.listen(5)
    while True:
        Process(target=httpproxy,args=soc.accept()).start()
