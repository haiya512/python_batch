#!/usr/local/bin/env python
#-*- coding:utf-8 -*-
###程序思想：把命令写到一个文件里，然后程序读这个文件去执行
###命令
#Auth LiYong
#2012-11-30

import pexpect,sys,time,os
import fileinput,glob,string
import signal,datetime
#import multiprocessing 
import threading
import Queue
import socket
from optparse import OptionParser

global sshtimeout
sshtimeout = 300
telnettimeout = 10
mergefiletimeout = 300
startrecord_ = datetime.datetime.now()
startrecord = startrecord_.strftime("%Y%m%d_%H%M%S")
startdate = startrecord_.strftime("%Y%m%d")
starttime = startrecord_.strftime("%H%M%S")
Qserverlist = Queue.Queue()
Qserverfail = Queue.Queue()
Qserversucs = Queue.Queue()
failhostlist = []

##日志目录
logdir = os.getcwd() + '/log/' + startdate + '/' + starttime + '/' ## must be in end of "/" 
if not os.path.exists(logdir):
  os.makedirs(logdir)
## 临时日志文件
tmp_log_prefix_filename = startrecord + '_'
tmp_logdir_and_prefix_filename = logdir  + tmp_log_prefix_filename
## expect 执行时间时成功日志
pexpectbatchlog = logdir + 'log_pexpectbatch_' + startrecord
## expect 执行时间时失败日志
pexpectbatcherrlog = logdir + 'error_pexpectbatch_' + startrecord

class Notcmd: pass
class Notpwd: pass
class Neterr: pass
#class Pwderr: pass

##颜色定义类
class printcolor:
  def red(self,value):
    print "\033[1;31;40m"+value+"\033[0m"
  def green(self,value):
    print "\033[1;32;40m"+value+"\033[0m"
  def yellow(self,value):
    print "\033[1;33;40m"+value+"\033[0m"

###ping 函数
def ping(ip,port,timeout=telnettimeout):  
    cs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    address=(str(ip),int(port))
    cs.settimeout(timeout)
    ##如果成功返回0
    return cs.connect_ex((address))

#class Mssh(multiprocessing.Process):
class Mssh(threading.Thread):
      def __init__(self,ip,user,passwd,cmd,port,debug,sshtimeout):
         #multiprocessing.Process.__init__(self)
         threading.Thread.__init__(self)
         self.ip=ip
         self.user=user
         self.passwd=passwd
         self.cmd=cmd
         self.port=port
         self.debug=debug
         self.sshtimeout=sshtimeout
         self.telnettimeout=telnettimeout
         self.failhostlist=failhostlist
         self.pexpectbatcherrlog=pexpectbatcherrlog
  
      def run(self):
        
        try:
          if not cmd: raise Notcmd
          if not passwd: raise Notpwd
          if not ping(self.ip,self.port,telnettimeout) == 0: raise Neterr
          now=time.strftime("%Y-%m-%d %H:%M:%S")
          ##是否开启debug模式
          if debug == None:
            mlog=tmp_logdir_and_prefix_filename + self.ip + '.log'
            f = open(mlog,"a+")
            ssh = pexpect.spawn('ssh -o stricthostkeychecking=no %s@%s -p%s' % (self.user, self.ip, self.port),timeout=self.sshtimeout)
            f.write('\n################   %s start at: %s  #############\n'%(self.ip,now))
            ssh.logfile_read = f
            sys.stdout.flush()
          else :
            f=open('/tmp/tmp.log',"a+b")
            ssh = pexpect.spawn('ssh -o stricthostkeychecking=no %s@%s -p%s' % (self.user, self.ip, self.port),timeout=self.sshtimeout)
            ssh.logfile_read=sys.stdout
          print "Start time:            %s ----- %s " % (now , self.ip)
          i = ssh.expect(['(?i)password','continue connecting (yes/no)?','[$#]','No route to host','Connection refused','pexpect.TIMEOUT'])

          if i == 0:
             ssh.sendline(self.passwd)
          elif i == 1:
             ssh.sendline('yes')
             ssh.expect('password')
             ssh.sendline(self.passwd)
          elif i == 2:
             ssh.sendline()
          elif i == 3:
             raise Exception("SSH No Route To Host: %s" % self.ip)
          elif i == 4:
             raise Exception("SSH Connection refused: %s" % self.ip)
          else :
             raise Exception("pexpect.TIMEOUT: %s" % self.ip)

          #ssh.expect('(?i)terminal type\?')
          #ssh.sendline('vt100')

          if user == 'root':
             pass
          else :
             ssh.expect('$')
             ssh.sendline('sudo su -')
             i = ssh.expect(['#','[pP]assword','Access denied','Permission denied'])
             if i == 0:
                ssh.sendline()
             elif i == 1:
                raise Exception("Auth fail: %s" % self.ip)
             elif i == 2:
                raise Exception("Access denied: %s" % self.ip)
             elif i == 3:
                raise Exception("Permission denied: %s" % self.ip)
             else : 
                raise Exception("Other errors: %s" % self.ip)
          ssh.expect('#')
          ssh.sendline(cmd)
          ssh.expect('#')
          ssh.sendline()
          f.write('\n####################   %s  task finished        ##################\n'%self.ip)
          Qserversucs.put(self.ip)
          f.flush()
          sys.stdout.flush()
          f.close()
        except Notcmd:
          os.system('echo Error: === %s === MSSH not command >> %s '% (self.ip,self.pexpectbatcherrlog))
          printcolor().red("Error: MSSH not command %s" % self.ip)
          self.failhostlist.append(self.ip)
          sys.exit(1)
        except Notpwd:
          os.system('echo Error: === %s === MSSH not passwd >> %s '% (self.ip,self.pexpectbatcherrlog))
          printcolor().red("Error: MSSH not passwd %s" % self.ip)
          self.failhostlist.append(self.ip)
          sys.exit(1)
        except Neterr:
          os.system('echo Error: === %s === Can not telnet >> %s '% (self.ip,self.pexpectbatcherrlog))
          printcolor().red("Error: Can not telnet %s %s" % (self.ip,self.port))
          self.failhostlist.append(self.ip)
          sys.exit(1)
        #except Pwderr:
        #  ssh.close
        #  os.system('echo Error: === %s === Passwd error >> %s '% (self.ip,self.pexpectbatcherrlog))
        #  print "Error: Passwd error. ", (self.ip,self.port)
        #  self.failhostlist.append(self.ip)
        #  sys.exit(1)
        except pexpect.EOF:
          ssh.close()
          os.system('echo Error: === %s === pexpect.EOF >> %s '% (self.ip,self.pexpectbatcherrlog))
          printcolor().red('Error: === %s === pexpect.EOF' % self.ip)
          self.failhostlist.append(self.ip)
          f.flush()
          f.close()
          sys.exit(1)
        except pexpect.TIMEOUT:
          ssh.close()
          os.system('echo Error: === %s === MSSH Connect Tiomout >> %s '% (self.ip,self.pexpectbatcherrlog))
          printcolor().red("Error: MSSH Connect Tiomout: %s" % self.ip)
          self.failhostlist.append(self.ip)
          f.flush()
          f.close()
          sys.exit(1)
        except Exception,e :
          ssh.close()
          os.system('echo Error: === %s === %s >> %s '% (self.ip,str(e),self.pexpectbatcherrlog))
          printcolor().red("Error: %s" % str(e))
          self.failhostlist.append(self.ip)
          f.flush()
          f.close()
          sys.exit(1)
        else:
          ssh.close()
          f.close()
        finally:  
          time.sleep(0.01)

def Argument(Print="No"):
  parser = OptionParser(usage="%prog -f hostlist -u user -p passwd [-c \"cmd\" or -C \"commandfile\"] versrion 1.1",version="%prog LiYong")
  parser.add_option("-f", "--file",dest="File",action="store",help="host list ,which stores ip and password")
  parser.add_option("-u", "--user",action="store", dest="User",help="username,root or other users")
  parser.add_option("-p", "--passwd",action="store", dest="Passwd",help="user's password")
  parser.add_option("--port",action="store", dest="Port",help="sshd's port ,default:57522")
  parser.add_option("-d", "--debug",action="store_true", dest="debug",help="Output debug messages")
  parser.add_option("-c", "--cmd",action="store", dest="Cmd",
    help="command to be exected,don't forget to type \"\", e.g \"ifconfig\"\n ")
  parser.add_option("-C", "--commandfile",dest="Commandfile",action="store",help="cmd list,stores cmds")

  (options, args) = parser.parse_args()
  ArgvDict = vars(options)
  if Print == "Yes" : parser.print_help()
  return ArgvDict

##信号处理，比如突然想杀掉所有进程
def signal_handler(signal, frame):
  print "Notice: Kill All Process"
  sys.exit(0)

def Main():
  count = 0
  hostlist=[]
  commandlist=[]
  global start
  start = datetime.datetime.now()
  ArgvDict = Argument()
  File = ArgvDict["File"]
  Commandfile = ArgvDict["Commandfile"]
  global user
  user = ArgvDict["User"]
  global cmd
  cmd = ArgvDict["Cmd"]
  global debug
  debug = ArgvDict["debug"]
  global port
  port = ArgvDict["Port"]
  global passwd
  passwd = ArgvDict["Passwd"]

  signal.signal(signal.SIGINT, signal_handler)
  
  if Commandfile and cmd: 
      printcolor().red('Error: only need one of command or command file.')
      sys.exit(1)
  if (not Commandfile) and (not cmd):
      printcolor().red('Error: not command or command file.')
      sys.exit(1)
  if Commandfile:
    commandfile = open(Commandfile,"r")
    try:
      while True:
        commandline = commandfile.readline()
        if len(commandline) == 0:break
        if commandline[0] == "#" : continue
        commandlist.append(commandline)
      cmd_ = ';'.join(commandlist).replace('\n','')
      cmd = cmd_.replace(';;',';')

    except Exception,e:
      printcolor().red("\nError: %s" % str(e),"\n")
    finally:
      commandfile.close()

  file = open(File,"r")
  try:
    while True:
      line = file.readline()
      if len(line) == 0:break
      i = line.strip()
      if i[0] == "#" : continue
      host= i.split()
      Qserverlist.put(host)
    count = Qserverlist.qsize()
    global k
    k = 0
    if cmd.find('mysql') >= 0:
       global sshtimeout
       sshtimeout = 10800
    if user == None:
       user = 'root'
    while not Qserverlist.empty():
       i = Qserverlist.get()
       ip = i[0]
       if len(i) >= 2:
          port = i[1]
       else:
          if not port:
             port = 57522
       if len(i) >= 3:
           passwd = i[2]
       k += 1
       time.sleep(0.09)
       p=Mssh(ip,user,passwd,cmd,port,debug,sshtimeout)
       print "Now number is %d/%d" % (k,count)
       x=[]
       x.append(p)
       p.start()
       time.sleep(0.01)
       if k == count:
          time.sleep(1)
          print '\n#############################################\n'
          print "Notice: All commands have been send to: === %d Servers === " % k
          print "Notice: The commands are: %s " % cmd
          print "Notice: Time consuming %s" % (datetime.datetime.now()-start)
          print "Warnning: The commands are runnings now,pls wait a momment."
          break
    for t in x:
      t.join()
  except Exception,e:
    printcolor().red("\nError: %s" % str(e),"\n")
  finally:
    file.close()
  return count


if __name__ == "__main__":
  if len(sys.argv[1:]) >= 3:
    count = Main()
    #end = datetime.datetime.now()
    #print "Notice: Time consuming %s" % (end-start)
    ## wait for all server log into files. 
    while count != Qserversucs.qsize() + len(failhostlist):
        time.sleep(3)
        printcolor().yellow('Warnning: %d(count) != %d(Qserversucs) + %d(failconut),pls wait 3s.' % (count,Qserversucs.qsize(),len(failhostlist)))
        continue

    print 'Notice: Start to merge log files now, you cat type === cat %s*.log ===  to view it manual.' % logdir
    start_ = time.time()
    while True:
        if time.time() - start_ > mergefiletimeout:
           printcolor().red('Error: Merge File Timeout, Please Check')
           print 'Notice: You Can Type === cat %s*.log === to view ran log.' % logdir
           break
        if Qserversucs.empty():
           time.sleep(5)
           print 'Notice: All log file which ran command create merge finished.'
           print 'Notice: You Can Type === cat %s === to view ran log.' % pexpectbatchlog
           if failhostlist:
              printcolor().red('\nError: There are ===  %d Servers === ran failed.' % len(failhostlist))
              os.system('echo -ne "\nFailHostList: %s Servers Fail === %s ===\n" >> %s '% (len(failhostlist),failhostlist,pexpectbatcherrlog))
              printcolor().red('Error: The server list count not run command is %s' % failhostlist)
              printcolor().red('Error: pls rerun the command in the list.')
              printcolor().red('Error: You Can Type === cat %s* === to view ran log.' % logdir)
           else:
              printcolor().green('Ok: All task finished in === %d Servers ===' % k)
           break
        else:
           logprefixandip = tmp_log_prefix_filename + Qserversucs.get()
           os.system('cat %s%s.log >> %s'% (logdir, logprefixandip, pexpectbatchlog))
           os.system(r'rm -f %s%s.log'% (logdir,logprefixandip))
    print '\n#############################################\n'

  else:
    Argument(Print="Yes")
    sys.exit(1)
