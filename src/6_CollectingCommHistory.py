import json 
import subprocess
import os
import re

import time

homePath = os.getcwd() ## /VRUNY/
LineNumListPath = homePath + "/output/LineNumList.json"
DiffPath = homePath + "/data/diffs/"
ClonePath = homePath + "/data/clones/"
CtagPath = homePath + "/ctags/ctags"
#=# Output
CommHistoryPath = homePath + "/data/CommitHistory/"


shouldMake = [CommHistoryPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)


def ExtractTargetComm(Pack, Diff):
    try:
        with open(os.path.join(DiffPath + Pack + '/', Diff + ".diff"), "r", encoding = "UTF-8") as f:
            DiffData  = "".join(f.readlines())
    except UnicodeDecodeError:
        with open(os.path.join(DiffPath + Pack + '/', Diff + ".diff"), "r", encoding = "ISO-8859-1") as f:
            DiffData  = "".join(f.readlines())
    
    URL = DiffData.split("\n")[0].split("URL:")[1]
    return URL.split("/")[-1]


def SaveGitLog(Pack, FileName, TargetComm): ## use checkout + use ctags
    os.chdir(ClonePath + Pack)
    
    try: 
        checkoutCommand	= subprocess.check_output("git checkout -f " + TargetComm, stderr = subprocess.STDOUT, shell = True)
        time.sleep(1)
        
        FuncName = FileName.split('@@')[-1]
        FilePath = "/".join(FileName.split("@@")[1:-1])
        finding_cfiles = subprocess.check_output(CtagPath + ' --fields=+ne -o - --sort=no ' + FilePath, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
        
        alllist = str(finding_cfiles) 
        for result in alllist.split('\n'): 
            if result == '' or result == ' ' or result == '\n':
                continue

            funcname = result.split('\t')[0]
            if len(result.split('\t')) < 7:
                continue

            if (funcname == FuncName) and \
                (result.split('\t')[3] =='f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6]):
                    startline = result.split('\t')[4].replace('line:', '')
                    endline = result.split('\t')[-1].replace('end:', '')  
        
                    if not os.path.isdir(CommHistoryPath + Pack):
                        os.mkdir(CommHistoryPath + Pack)
                    
                    Command = "git log " + TargetComm + " -L " + startline + "," + endline + ":" + ClonePath + Pack + "/" + FilePath + " > " + CommHistoryPath + Pack + "/" + FileName + ".log"
                    result = subprocess.check_output(Command, stderr=subprocess.STDOUT, shell=True) 
                    print ('[1] Now parsing ' + Command + '..')
                    
    except subprocess.CalledProcessError as e:
        print("GitLogError1 : " + str(Pack) + " : " + str(FileName) + " : " + str(e))



def SaveGitLog1(Pack, FileName, TargetComm):
    os.chdir(ClonePath + Pack)
    
    try:
        checkoutCommand	= subprocess.check_output("git checkout -f " + TargetComm, stderr = subprocess.STDOUT, shell = True)
        time.sleep(1)
        
        FuncName = FileName.split('@@')[-1]
        FilePath = "/".join(FileName.split("@@")[1:-1])
        
        Command = "git log " + TargetComm + " -L:" + FuncName + ":" + ClonePath + Pack + "/" + FilePath + " > " + CommHistoryPath + Pack + "/" + FileName + ".log"
        result = subprocess.check_output(Command, stderr=subprocess.STDOUT, shell=True) 
        print ('[2] Now parsing ' + Command + '..')
        
    except subprocess.CalledProcessError as e:
        print("GitLogError2 : " + str(Pack) + " : " + str(FileName) + " : " + str(e))


def SaveGitLog2(Pack, FileName, TargetComm):
    os.chdir(ClonePath + Pack)
    
    try:
        checkoutCommand	= subprocess.check_output("git checkout -f " + TargetComm, stderr = subprocess.STDOUT, shell = True)
        time.sleep(1)
            
        FuncName = FileName.split('@@')[-1]
        FilePath = "/".join(FileName.split("@@")[1:-1])
        
        Command = "git log " + TargetComm + " -L:" + FuncName + ":" + ClonePath + Pack + "/" + FilePath + " > " + CommHistoryPath + Pack + "/" + FileName + ".log"
        result = subprocess.check_output(Command, stderr=subprocess.STDOUT, shell=True) 
        print ('[3] Now parsing ' + Command + '..')
        
    except subprocess.CalledProcessError as e:
        print("GitLogError3 : " + str(Pack) + " : " + str(FileName) + " : " + str(e))
    

def CollectGitLog(LineList): 
    for Pack in LineList:
        for FileName in LineList[Pack]:            
            Diff = FileName.split("@@")[0]
            TargetComm = ExtractTargetComm(Pack, Diff)
            if TargetComm == None:
                continue
                
            if not os.path.isfile(CommHistoryPath + Pack + "/" + FileName + ".log"):
                SaveGitLog(Pack, FileName, TargetComm) 
                if not os.path.isfile(CommHistoryPath + Pack + "/" + FileName + ".log"):
                    SaveGitLog1(Pack, FileName, TargetComm) 
            
            if os.path.isfile(CommHistoryPath + Pack + "/" + FileName + ".log") and \
                os.stat(CommHistoryPath + Pack + "/" + FileName + ".log").st_size == 0:
                    SaveGitLog2(Pack, FileName, TargetComm) 

def main():    
    f1 = open(LineNumListPath, 'r')
    LineList = json.load(f1)
    
    CollectGitLog(LineList) 


if __name__ == "__main__":
	main()