import json 
import subprocess
import os
import re

import Levenshtein


homePath = os.getcwd() ## /VRUNY/
DiffPath = homePath + "/data/diffs/"
CommHistoryPath = homePath + "/data/CommitHistory/"
DepPath = homePath + "/output/DepList.json"
#=# Output
CommHashPath = homePath + "/output/PotentialVICList.json"


def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from ReDeBug.)
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	# Code for normalizing the input string.
	# LF and TAB literals, curly braces, and spaces are removed,
	# and all characters are lowercased.
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
		' ')).lower()

def LineFiltering(string):
    pattern = removeComment(string)
    pattern = normalize(pattern)
    if len(pattern) == 0:
        return pattern
    
    pattern = re.sub(r'^(\/\*|\/\/|\*\/).*', "", pattern) # remove /*, //, */
    if (len(pattern) != 0) and (pattern[0] == "*") and ("=" not in pattern): 
        pattern = re.sub(r'^(\*).*', "", pattern)
    
    return pattern


def ExtractTargetComm(Pack, Diff):
    try:
        with open(os.path.join(DiffPath + Pack + '/', Diff + ".diff"), "r", encoding = "UTF-8") as f:
            DiffData  = "".join(f.readlines())
    except UnicodeDecodeError:
        with open(os.path.join(DiffPath + Pack + '/', Diff + ".diff"), "r", encoding = "ISO-8859-1") as f:
            DiffData  = "".join(f.readlines())
    
    URL = DiffData.split("\n")[0].split("URL:")[1]
    return URL.split("/")[-1]


def ExtractAllCommHash(Pack, FileName, TargetComm):
    AllCommHash = {}
    
    try:
        try:
            with open(CommHistoryPath + Pack + "/" + FileName + ".log", 'r', encoding = "UTF-8") as f:
                result = ''.join(f.readlines())     
                CommitBlocks = re.split(r'(commit [0-9a-f]{40}\nAuthor:)', result)
        except:
            with open(CommHistoryPath + Pack + "/" + FileName + ".log", 'r', encoding = "ISO-8859-1") as f:
                result = ''.join(f.readlines())     
                CommitBlocks = re.split(r'(commit [0-9a-f]{40}\nAuthor:)', result)

        for i in range(1, len(CommitBlocks), 2):
            Commit = CommitBlocks[i] + CommitBlocks[i+1]
            
            CommitHash = Commit.split('commit ')[1].split('\n')[0]
            try: 
                CommitCode = Commit.split('diff --git ')[1].split('@@')[2]
                AllCommHash[CommitHash] = CommitCode
            except IndexError as e:
                print("IndexError: " + str(Pack) + " : " + str(FileName) + " : " + str(CommitHash)) 
        
    except UnicodeDecodeError as e:
        print("UnicodeDecodeError: " + str(Pack) + " : " + str(FileName) + " : " + str(e))
    except FileNotFoundError as e:
        print("FileNotFoundError : " + str(Pack) + " : " + str(FileName) + " : " + str(e)) 
    
    FinalAllCommHash = {}
    flag = False

    for key, value in AllCommHash.items():
        if flag:
            FinalAllCommHash[key] = value
        if key.startswith(TargetComm):
            flag = True
    
    if len(FinalAllCommHash) == 0:
        FinalAllCommHash = AllCommHash
    
    return FinalAllCommHash    


def levenshtein_distance(line_str1, line_str2): ## reference: V-SZZ
    l1 = ''.join(line_str1.strip().split())
    l2 = ''.join(line_str2.strip().split())
    return Levenshtein.ratio(l1, l2)


def FindDELLine(ChangeCommHash, CommHash, CommHashIDX, del_f_lines, TargetCode):    
    Flag = True
    compare_thres = 0.0 
    final_del_f_line = TargetCode
    for del_f_line in del_f_lines:  
        ## slicing line mapping
        if len(TargetCode) > len(del_f_line):
            for i in range(len(TargetCode) - len(del_f_line) + 1):
                thres = levenshtein_distance(TargetCode[i:i + len(del_f_line)].lower(), del_f_line.lower())
                if thres >= 0.75: # using Levenshtein distance
                    if thres >= compare_thres: 
                        Flag = False
                        compare_thres = thres
                        final_del_f_line = del_f_line
    
        elif len(TargetCode) < len(del_f_line):
            for i in range(len(del_f_line) - len(TargetCode) + 1):
                thres = levenshtein_distance(del_f_line[i:i + len(TargetCode)].lower(), TargetCode.lower())
                if thres >= 0.75: # using Levenshtein distance
                    if thres >= compare_thres: 
                        Flag = False
                        compare_thres = thres
                        final_del_f_line = del_f_line
    
        elif len(TargetCode) == len(del_f_line):
            thres = levenshtein_distance(TargetCode.lower(), del_f_line.lower())             
            if thres >= 0.75: # using Levenshtein distance
                if thres >= compare_thres: 
                    Flag = False
                    compare_thres = thres
                    final_del_f_line = del_f_line
    
    TargetCode = final_del_f_line
    if CommHash not in ChangeCommHash:
        ChangeCommHash[CommHashIDX] = CommHash
    
    return ChangeCommHash, TargetCode


def FindADDLine(ChangeCommHash, CommHash, CommHashIDX, f_lines, TargetCode):     
    if ("+"+TargetCode) in f_lines:
        del_f_lines = []
        for f_line in f_lines:
            if f_line.startswith("-"):
                del_f_lines.append(f_line[1:])
        
        ChangeCommHash, TargetCode = FindDELLine(ChangeCommHash, CommHash, CommHashIDX, del_f_lines, TargetCode)
    
    return ChangeCommHash, TargetCode


def ExtractChangeCommHash(AllCommHash, LineCode):
    ChangeCommHash = {}
    for CommHashIDX, (CommHash, CommCode) in enumerate(AllCommHash.items()):
        f_lines = []
        lines = CommCode.split('\n')
        for line in lines:
            f_line = LineFiltering(line)
            if len(f_line) == 0 or len(f_line) == 1:
                continue
            
            if f_line[0] == "+" or f_line[0] == "-":
                f_lines.append(f_line)

        f_LineCode = LineFiltering(LineCode)
        ChangeCommHash, TargetCode = FindADDLine(ChangeCommHash, CommHash, CommHashIDX, f_lines, f_LineCode)
        LineCode = TargetCode
        
    return ChangeCommHash


def SaveCommHashList(CommHashList, Pack, FileName, Flag, TargetComm, TargetData, CommList):
    if Pack not in CommHashList:
        CommHashList[Pack] = {}
    if FileName not in CommHashList[Pack]:
        CommHashList[Pack][FileName] = {}
    if "VFC" not in CommHashList[Pack][FileName]:
        CommHashList[Pack][FileName]["VFC"] = TargetComm
        CommHashList[Pack][FileName].update(TargetData)
        
    CommHashList[Pack][FileName][Flag+"_CommList"] = CommList
    
    return CommHashList


def ExtractCommHash(CPGLineData):
    CommHashList = {}
    
    for Pack in CPGLineData:
        for FileName in CPGLineData[Pack]:            
            print("FileName: "+str(FileName))
            
            Diff = FileName.split("@@")[0]
            TargetComm = ExtractTargetComm(Pack, Diff)
                
            if not os.path.isfile(CommHistoryPath + Pack + "/" + FileName + ".log"):
                CommHashList = SaveCommHashList(CommHashList, Pack, FileName, "GitLogError", TargetComm, CPGLineData[Pack][FileName], {})
                continue
            
            AllCommHash = ExtractAllCommHash(Pack, FileName, TargetComm)                
            
            if "Vul_VAL" in CPGLineData[Pack][FileName]:       
                CommList = {}
                for Line in CPGLineData[Pack][FileName]["Vul_VAL"]:
                    LineNum = Line.split('@@')[0]
                    LineCode = Line.split('@@')[1]

                    ChangeCommHash = ExtractChangeCommHash(AllCommHash, LineCode)            
                    CommList[LineNum+"@@"+LineCode] = ChangeCommHash

                CommHashList = SaveCommHashList(CommHashList, Pack, FileName, "Vul", TargetComm, CPGLineData[Pack][FileName], CommList)
            if "Pat_VAL" in CPGLineData[Pack][FileName]: 
                CommList = {}
                for Line in CPGLineData[Pack][FileName]["Pat_VAL"]:
                    LineNum = Line.split('@@')[0]
                    LineCode = Line.split('@@')[1]

                    ChangeCommHash = ExtractChangeCommHash(AllCommHash, LineCode)            
                    CommList[LineNum+"@@"+LineCode] = ChangeCommHash

                CommHashList = SaveCommHashList(CommHashList, Pack, FileName, "Pat", TargetComm, CPGLineData[Pack][FileName], CommList)
    
    return CommHashList


def SaveResult(VICList, VICPath):
    with open(VICPath, "w") as f:
        json.dump(VICList, f, indent = 4)
    f.close()


def main():
    f = open(DepPath, 'r')
    CPGLineData = json.load(f)
    
    CommHashList = ExtractCommHash(CPGLineData)
    SaveResult(CommHashList, CommHashPath)


if __name__ == "__main__":
	main()
